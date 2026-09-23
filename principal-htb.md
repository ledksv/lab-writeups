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
