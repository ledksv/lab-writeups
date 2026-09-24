# Delivery

**Platform:** HackTheBox
**OS:** Linux
**Tags:** osTicket, Mattermost, Email Abuse, MySQL, bcrypt, Hash Cracking, Password Reuse
**Date:** 2026-09-24

Three services on the box. The trick is noticing that osTicket hands you a working `@delivery.htb` mailbox when you open a ticket, and Mattermost's email verification lands straight in that ticket thread. From there credentials in an internal chat channel give SSH access, and a bcrypt hash in the Mattermost database cracks in seconds once you know the base word.

## 0. Attack Chain

1. Recon finds SSH (22), nginx (80), and Mattermost 5.30.1 (8065)
2. Port 80 reveals `helpdesk.delivery.htb` running osTicket. Mattermost only lets you register with an `@delivery.htb` email
3. Opening an osTicket ticket gives you a `<number>@delivery.htb` address - the Mattermost verification email lands in that ticket thread
4. Verify the Mattermost account, join the Internal team, read root's posts leaking `maildeliverer:Youve_G0t_Mail!` and a hint about passwords being variants of `PleaseSubscribe!`
5. SSH in as `maildeliverer` - user flag
6. Read Mattermost `config.json`, MySQL creds, dump the Users table, root's bcrypt hash
7. Crack with `john` + `best64` rule seeded with `PleaseSubscribe!` - result: `PleaseSubscribe!21`
8. `su root` with the cracked password - root flag

## 1. Enumeration

```bash
nmap -sV -sC -p- 10.129.62.115
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2
80/tcp   open  http    nginx 1.14.2
8065/tcp open  http    Golang net/http - Mattermost
```

Mattermost version came from the `X-Version-Id` response header: **5.30.1**.

Port 80 landing page referenced a helpdesk and Mattermost, and said you need an `@delivery.htb` email to register. Added to `/etc/hosts`:

```
10.129.62.115   delivery.htb helpdesk.delivery.htb
```

- `delivery.htb:80` - static welcome page
- `helpdesk.delivery.htb` - osTicket support portal
- `delivery.htb:8065` - Mattermost

**Dead end - subdomain brute force:** Fuzzing `FUZZ.helpdesk.delivery.htb` only returned `Size: 0` hits - empty responses from the wildcard vhost, not real subdomains. I was fuzzing a level too deep. `Size: 0` matches are noise, don't chase them. The two hostnames already found were enough.

## 2. Foothold

### 2.1 Getting a valid @delivery.htb address

Mattermost requires a verified `@delivery.htb` email to register. We don't own the domain but osTicket does. Every new ticket gets assigned a `<ticket-number>@delivery.htb` address and any mail sent to it shows up in the public ticket thread.

1. Open a new ticket on osTicket, note the assigned ticket email e.g. `2590443@delivery.htb`
2. Register a Mattermost account using that address
3. Mattermost sends its verification email to `2590443@delivery.htb`
4. Open the ticket in osTicket and read the verification link from the thread
5. Follow the link - account verified

### 2.2 Credentials from Mattermost

The Internal channel had posts from root:

```
Credentials to the server are maildeliverer:Youve_G0t_Mail!

stop re-using the same passwords everywhere... Especially variants of "PleaseSubscribe!"

PleaseSubscribe! may not be in RockYou but hashcat rules can crack all variations easily
```

SSH creds for the foothold and a hint about root's password structure.

### 2.3 SSH - user flag

```bash
ssh maildeliverer@10.129.62.115
# password: Youve_G0t_Mail!
```

**Dead end - couldn't log back in after logging out:** Got "Permission denied" on the second attempt. Not a lockout - easy to fat-finger `Youve_G0t_Mail!` at a no-echo prompt. The `0` in `G0t` is a zero and `!` gets mangled by zsh history expansion. Used sshpass after that:

```bash
sshpass -p 'Youve_G0t_Mail!' ssh -o PreferredAuthentications=password maildeliverer@10.129.62.115
```

Single-quoting stops zsh from expanding the `!`. Worked every time.

**Result:** Shell obtained. User flag retrieved.

## 3. Privilege Escalation

### 3.1 Local enumeration

```bash
id
sudo -l
find / -user root -perm /4000 2>/dev/null
```

No sudo, SUID list was all stock Debian - nothing in `/opt` or `/usr/local`, nothing GTFOBins-able. No classic Linux vectors. The target is the application data.

### 3.2 Mattermost config

```bash
cat /opt/mattermost/config/config.json
```

`SqlSettings.DataSource`:
```
mmuser:Crack_The_MM_Admin_PW@tcp(127.0.0.1:3306)/mattermost
```

### 3.3 MySQL

**Dead end - password as positional arg:** `mysql -u mmuser -p Crack_The_MM_Admin_PW` fails with "Access denied to database 'Crack_The_MM_Admin_PW'" - with a space after `-p`, mysql reads the token as the database name, not the password. Enter the password at the prompt instead.

```bash
mysql -u mmuser -p
# enter Crack_The_MM_Admin_PW at prompt
```

### 3.4 Dump the hash

**Dead end - case sensitive table name:** `select * from users` fails. Table names are case-sensitive here - it is `Users`, not `users`.

```sql
use mattermost;
SELECT Username, Password FROM Users WHERE Username='root';
```

Root's hash:
```
$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO
```

bcrypt, cost 10.

### 3.5 Cracking

Root told us the password is a variant of `PleaseSubscribe!`. bcrypt is too slow to brute force but with a one-word base and a rule set it cracks fast.

**Dead end - hashcat rule file missing:** `/usr/share/hashcat/rules/best64.rule` did not exist. Found best64 in John's rules instead: `/usr/share/john/rules/best64.rule`. Don't feed one tool's rule file to the other - reference it by name through the tool that owns it.

```bash
echo '$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO' > root.hash
echo 'PleaseSubscribe!' > base.txt
john --wordlist=base.txt --rules=best64 root.hash
```

Result: `PleaseSubscribe!21` - cracked in under a second.

### 3.6 Root

```bash
su root
# PleaseSubscribe!21
```

Root flag retrieved.

## 4. Flags

- User: `redacted`
- Root: `redacted`

---

## Penetration Test Report

**Reference:** HTB-DEL-01  
**Date:** 24 September 2026  
**Target:** delivery.htb / 10.129.62.115 / Debian 10

---

### Executive Summary

Testing of delivery.htb identified four findings that together produced full root compromise. A support ticketing system exposed a usable `@delivery.htb` mailbox, allowing Mattermost's domain-based email verification to be bypassed without owning the domain. Once inside Mattermost, an internal channel contained plaintext SSH credentials and a hint that system passwords were variants of a known phrase. The Mattermost database configuration file was readable by the low-privilege foothold account, exposing MySQL credentials. A bcrypt hash extracted from the database was cracked in under a second using a rule attack seeded from the hint left in chat, and the cracked password was reused as the system root password.

**Impact:** Full root compromise. All files, credentials, services and network connections accessible from the host are exposed.

**Priority recommendations:**
1. Segregate helpdesk mail from identity verification. Do not use a publicly accessible ticketing system's email domain to gate access to other internal services.
2. Never store or share plaintext credentials in chat. Use a secrets manager for all service credentials.
3. Restrict `config.json` permissions so that the application service account cannot be used to read database credentials from the filesystem.
4. Enforce unique, high-entropy passwords per account. Passwords derived from a common phrase are trivially cracked with rule-based attacks regardless of the hash algorithm used.

---

### Findings Summary

| Reference | Finding | Severity |
|-----------|---------|----------|
| F-01 | osTicket email domain abuse bypasses Mattermost verification | High |
| F-02 | Plaintext SSH credentials posted in Mattermost internal channel | High |
| F-03 | Mattermost config.json readable by low-privilege user exposes database credentials | Medium |
| F-04 | Password reuse and weak derivation pattern leads to root compromise | Critical |

---

### Compromise Sequence

| Stage | Action | Access obtained |
|-------|--------|----------------|
| 01 | Opened an osTicket support ticket to obtain a `@delivery.htb` mailbox. Used the address to register a Mattermost account and read the verification email from the ticket thread. | Mattermost account |
| 02 | Reviewed the Internal channel. Found plaintext SSH credentials `maildeliverer:Youve_G0t_Mail!` posted by root, along with a hint that passwords are variants of `PleaseSubscribe!`. | SSH credentials |
| 03 | Authenticated over SSH as `maildeliverer`. Read `/opt/mattermost/config/config.json` to obtain MySQL credentials. Dumped the Mattermost Users table to extract root's bcrypt hash. | User shell, bcrypt hash |
| 04 | Cracked the bcrypt hash with John using the `best64` rule seeded with `PleaseSubscribe!`. Authenticated as root via `su` using the cracked password. | root shell |

---

### F-01: osTicket Email Domain Abuse Bypasses Mattermost Verification

**Severity:** High  
**CVSS 3.1:** 7.3 (AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N)  
**CWE:** CWE-287: Improper Authentication

**Description:** osTicket assigns every new support ticket a system address of the form `<number>@delivery.htb`. Any mail delivered to that address is visible in the public ticket thread. Mattermost's registration gate requires only an `@delivery.htb` email address and verifies it by sending a link to that address. By registering with the osTicket-issued address, the verification email is delivered into the ticket thread and the link is accessible without owning the domain.

**Prerequisites:** Network access to `helpdesk.delivery.htb` and `delivery.htb:8065`. No authentication required on either service.

**Impact:** Any unauthenticated user can obtain a verified Mattermost account and access internal team channels. Access to the Internal channel produced the SSH credentials used for the initial foothold.

**Steps to reproduce:**
1. Navigate to `http://helpdesk.delivery.htb/open.php` and open a new support ticket. Note the assigned ticket email address.
2. Navigate to `http://delivery.htb:8065` and register a Mattermost account using the ticket email address.
3. Return to osTicket and view the ticket thread. The Mattermost verification email will have been delivered there.
4. Copy the verification link from the ticket thread and follow it in a browser.
5. Log into Mattermost with the verified account and join the Internal team.

**Remediation:** Do not use a publicly accessible ticketing system's email domain as the trust anchor for internal service registration. Mattermost registration should require explicit administrator approval or use a domain that is not exposed via any public-facing mail handler.

---

### F-02: Plaintext SSH Credentials in Mattermost Internal Channel

**Severity:** High  
**CVSS 3.1:** 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)  
**CWE:** CWE-312: Cleartext Storage of Sensitive Information

**Description:** The Mattermost Internal channel contained a post from the root account disclosing the plaintext SSH credentials `maildeliverer:Youve_G0t_Mail!`. A separate post from the same account disclosed that system passwords across the environment are variants of the phrase `PleaseSubscribe!`. Both disclosures were directly used during this assessment.

**Prerequisites:** Access to the Mattermost Internal team channel (obtained via F-01).

**Impact:** Direct SSH access to the host as `maildeliverer`. The password derivation hint reduced the bcrypt cracking effort to under one second.

**Evidence:**
```
# Mattermost Internal channel posts from root:
"Credentials to the server are maildeliverer:Youve_G0t_Mail!"
"stop re-using the same passwords everywhere... Especially variants of PleaseSubscribe!"
"PleaseSubscribe! may not be in RockYou but hashcat rules can crack all variations easily"
```

**Remediation:** Never store or share plaintext credentials in any messaging or collaboration platform. Use a dedicated secrets manager for all service credentials. Rotate the `maildeliverer` account password and review all Mattermost channel history for other credential disclosures.

---

### F-03: Mattermost config.json Readable by Low-Privilege User

**Severity:** Medium  
**CVSS 3.1:** 5.5 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)  
**CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource

**Description:** The Mattermost configuration file at `/opt/mattermost/config/config.json` was readable by the `maildeliverer` account. The file contained the MySQL data source string including credentials for the `mmuser` database account in plaintext: `mmuser:Crack_The_MM_Admin_PW`. This allowed the contents of the Mattermost database to be read, including the password hash for the root account.

**Prerequisites:** Local shell access as any user that can read `/opt/mattermost/config/config.json`.

**Evidence:**
```json
"SqlSettings": {
    "DataSource": "mmuser:Crack_The_MM_Admin_PW@tcp(127.0.0.1:3306)/mattermost?..."
}
```

**Remediation:** Set the permissions on `/opt/mattermost/config/config.json` so that only the Mattermost service account can read it (`chmod 600`, owned by the Mattermost service user).

---

### F-04: Password Reuse and Weak Password Derivation Leads to Root

**Severity:** Critical  
**CVSS 3.1:** 7.8 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)  
**CWE:** CWE-521: Weak Password Requirements

**Description:** The system root password was a variant of the phrase `PleaseSubscribe!`, derived by appending common numeric characters. The same derivation pattern was disclosed by root in a Mattermost channel post (F-02). The bcrypt hash extracted from the Mattermost database (F-03) was cracked in under one second using John the Ripper with the `best64` rule set seeded with the base phrase. The cracked password authenticated directly as system root via `su`, indicating that the Mattermost admin account and the system root account shared the same derived password.

**Evidence:**
```bash
echo '$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO' > root.hash
echo 'PleaseSubscribe!' > base.txt
john --wordlist=base.txt --rules=best64 root.hash

# Result:
PleaseSubscribe!21   (?)
1g 0:00:00:00 DONE

# su to root:
su root
# PleaseSubscribe!21
root@Delivery:~# cat /root/root.txt
[redacted]
```

**Remediation:** Set a unique, randomly generated password for the system root account that has no relationship to any application account or shared phrase. Rotate all account passwords that may share the same base phrase.

---

### Evidence Index

| Reference | Description |
|-----------|-------------|
| E-01 | Mattermost verification link retrieved from osTicket ticket thread (section 2.1) |
| E-02 | Plaintext SSH credentials from Mattermost Internal channel, SSH foothold confirmed (section 2.2) |
| E-03 | MySQL credentials from config.json, root bcrypt hash extracted from Users table (sections 3.2 and 3.4) |
| E-04 | John rule-based crack result and su to root (sections 3.5 and 3.6) |
