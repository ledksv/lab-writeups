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

**Target:** delivery.htb
**Address:** 10.129.62.115
**Assessment type:** External network & web application assessment
**Assessment date:** 24 September 2026
**Environment:** HackTheBox laboratory assessment  |  Linux
**Prepared by:** Ledion Mujaj
**Reference:** HTB-DEL-01

---

## 1. Executive Summary

### Assessment outcome

Testing of **delivery.htb** identified four findings that together produced full root compromise. A support ticketing system exposed a usable `@delivery.htb` mailbox, allowing Mattermost's domain-based email verification to be bypassed without owning the domain. Once inside Mattermost, an internal channel contained plaintext SSH credentials and a hint that system passwords were variants of a known phrase. The Mattermost database configuration file was readable by the low-privilege foothold account, exposing MySQL credentials. A bcrypt hash extracted from the database was cracked in under a second using a rule attack seeded from the hint left in chat, and the cracked password was reused as the system root password.

### Impact

Full root compromise of the host. All files, credentials, services and network connections accessible from the host are exposed. The credential leak in chat and the password reuse pattern mean that a single compromised Mattermost account is sufficient to reach system root without any exploit code.

### Priority recommendations

1. Segregate helpdesk mail from identity verification. Do not use a publicly accessible ticketing system's email domain to gate access to other internal services.
2. Never store or share plaintext credentials in chat. Use a secrets manager for all service credentials.
3. Restrict `config.json` permissions so that the application service account cannot be used to read database credentials from the filesystem.
4. Enforce unique, high-entropy passwords per account. Passwords derived from a common phrase are trivially cracked with rule-based attacks regardless of the hash algorithm used.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Address | Description |
| --- | --- | --- |
| delivery.htb | 10.129.62.115 | Debian 10; nginx welcome page, osTicket support portal on helpdesk.delivery.htb, Mattermost 5.30.1 on port 8065. |
| Port | Service | Observed detail |
| --- | --- | --- |
| 22/tcp | SSH | OpenSSH 7.9p1 Debian 10+deb10u2 |
| 80/tcp | HTTP | nginx 1.14.2; static welcome page referencing helpdesk and Mattermost |
| 8065/tcp | HTTP | Golang net/http server (Mattermost 5.30.1) |

```
nmap -sV -sC -p- 10.129.62.115

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2
80/tcp   open  http    nginx 1.14.2
8065/tcp open  http    Golang net/http server (Mattermost)
  X-Version-Id: 5.30.0.5.30.1.57fb31b889bf81d99d8af8176d4bbaaa.false
```

Added delivery.htb and helpdesk.delivery.htb to /etc/hosts before beginning web enumeration. Mattermost version identified from the X-Version-Id response header.

### 2.2 Approach

Testing began with a full port scan and review of the two web services. The osTicket ticketing system was examined to understand its email handling behaviour. The Mattermost registration flow was tested using the osTicket-issued email address. After verifying the Mattermost account, the Internal channel was reviewed. SSH authentication was attempted with the credentials found in chat. Post-foothold enumeration covered sudo rights, SUID binaries and application configuration files. The Mattermost database was queried for user account hashes, and the root hash was submitted to John with a rule-based wordlist derived from the hint in chat.

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
| [F-01](#f-01-osticket-email-domain-abuse-bypasses-mattermost-verification) | osTicket email domain abuse bypasses Mattermost verification | **High** | 6 |
| [F-02](#f-02-plaintext-ssh-credentials-in-mattermost-internal-channel) | Plaintext SSH credentials posted in Mattermost internal channel | **High** | 7 |
| [F-03](#f-03-mattermost-configjson-readable-by-low-privilege-user) | Mattermost config.json readable by low-privilege user exposes database credentials | **Medium** | 8 |
| [F-04](#f-04-password-reuse-and-weak-password-derivation-leads-to-root) | Password reuse and weak derivation pattern leads to root compromise | **Critical** | 9 |

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | Opened an osTicket support ticket to obtain a `@delivery.htb` mailbox. Used the address to register a Mattermost account and read the verification email from the ticket thread. | Mattermost account |
| 02 | Reviewed the Internal channel. Found plaintext SSH credentials `maildeliverer:Youve_G0t_Mail!` posted by root, along with a hint that passwords are variants of `PleaseSubscribe!`. | SSH credentials |
| 03 | Authenticated over SSH as `maildeliverer`. Read `/opt/mattermost/config/config.json` to obtain MySQL credentials. Dumped the Mattermost Users table to extract root's bcrypt hash. | User shell, bcrypt hash |
| 04 | Cracked the bcrypt hash with John using the `best64` rule seeded with `PleaseSubscribe!`. Authenticated as root via `su` using the cracked password. | root shell |

### 3.3 Relationship between findings

F-01 is the entry point that provides Mattermost access required to reach F-02. F-02 provides the SSH credentials for the foothold and the base word needed for F-04. F-03 is an independent exposure that provides MySQL access and the hash needed for F-04. F-04 produces root. All four findings contributed to the compromise chain, and each represents an independent control failure that should be remediated separately.

## 4.1 osTicket Email Domain Abuse Bypasses Mattermost Verification

### F-01   osTicket ticket email / Mattermost registration - HIGH

| Field | Assessment |
| --- | --- |
| Description | osTicket assigns every new support ticket a system address of the form `<number>@delivery.htb`. Any mail delivered to that address is visible in the public ticket thread. Mattermost's registration gate requires only an `@delivery.htb` email address and verifies it by sending a link to that address. By registering with the osTicket-issued address, the verification email is delivered into the ticket thread and the link is accessible without owning the domain. |
| Prerequisites | Network access to `helpdesk.delivery.htb` and `delivery.htb:8065`. No authentication required on either service. |
| Impact | Any unauthenticated user can obtain a verified Mattermost account and access internal team channels. Access to the Internal channel produced the SSH credentials used for the initial foothold. |
| Affected system | helpdesk.delivery.htb (osTicket) / delivery.htb:8065 (Mattermost 5.30.1) |
| CVSS 3.1 | **7.3** (High) AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N |
| CWE | CWE-287: Improper Authentication |

### Steps to reproduce

1. Navigate to `http://helpdesk.delivery.htb/open.php` and open a new support ticket. Note the assigned ticket email address, e.g. `2590443@delivery.htb`.
2. Navigate to `http://delivery.htb:8065` and register a Mattermost account using the ticket email address.
3. Return to osTicket and view the ticket thread. The Mattermost verification email will have been delivered there.
4. Copy the verification link from the ticket thread and follow it in a browser.
5. Log into Mattermost with the verified account and join the Internal team.

### Evidence

```
# Mattermost verification email delivered to osTicket ticket thread:
http://delivery.htb:8065/do_verify_email?token=yncka67...&email=2590443%40delivery.htb

# After following the link:
# Account verified - access to Internal team channel granted
```

Evidence E-01. Mattermost verification link retrieved from the osTicket ticket thread without owning the delivery.htb mail domain.

### Remediation

Do not use a publicly accessible ticketing system's email domain as the trust anchor for internal service registration. Mattermost registration should require explicit administrator approval or use a domain that is not exposed via any public-facing mail handler. If osTicket must use the same domain, disable the public ticket email feature or restrict ticket thread visibility to authenticated staff only.

### Verification

Confirm that a new Mattermost account cannot be registered and verified using an email address obtained from an osTicket ticket. Verify that the registration flow requires administrator approval or that the trusted email domain is not accessible via the public ticketing system.

## 4.2 Plaintext SSH Credentials in Mattermost Internal Channel

### F-02   Mattermost Internal channel - credential disclosure - HIGH

| Field | Assessment |
| --- | --- |
| Description | The Mattermost Internal channel contained a post from the root account disclosing the plaintext SSH credentials `maildeliverer:Youve_G0t_Mail!`. A separate post from the same account disclosed that system passwords across the environment are variants of the phrase `PleaseSubscribe!` and noted that hashcat rule attacks would crack them. Both disclosures were directly used during this assessment. |
| Prerequisites | Access to the Mattermost Internal team channel (obtained via F-01). |
| Impact | Direct SSH access to the host as `maildeliverer`, providing the initial shell. The password derivation hint reduced the bcrypt cracking effort to under one second. |
| Affected system | delivery.htb:8065 - Mattermost Internal channel |
| CVSS 3.1 | **8.1** (High) AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| CWE | CWE-312: Cleartext Storage of Sensitive Information |

### Steps to reproduce

1. Obtain a verified Mattermost account via F-01.
2. Join the Internal team and review the channel history.
3. Read the credential post from the root account: `maildeliverer:Youve_G0t_Mail!`.
4. Authenticate over SSH: `ssh maildeliverer@10.129.62.115`.

### Evidence

```
# Mattermost Internal channel - posts from root:
"Credentials to the server are maildeliverer:Youve_G0t_Mail!"
"stop re-using the same passwords everywhere... Especially variants of PleaseSubscribe!"
"PleaseSubscribe! may not be in RockYou but hashcat rules can crack all variations easily"

# SSH authentication:
ssh maildeliverer@10.129.62.115
# Authentication successful

$ id
uid=1000(maildeliverer) gid=1000(maildeliverer) groups=1000(maildeliverer)
$ cat ~/user.txt
[redacted]
```

Evidence E-02. Plaintext SSH credentials retrieved from Mattermost Internal channel. SSH authentication confirmed with the disclosed credentials. Flag value redacted.

### Remediation

Never store or share plaintext credentials in any messaging or collaboration platform. Use a dedicated secrets manager for all service credentials. Rotate the `maildeliverer` account password immediately. Review all Mattermost channel history for other credential disclosures and rotate any credentials found.

### Verification

Confirm that no plaintext credentials are present in any Mattermost channel. Verify that the `maildeliverer` SSH password has been rotated and does not match any value previously disclosed in chat.

## 4.3 Mattermost config.json Readable by Low-Privilege User

### F-03   /opt/mattermost/config/config.json - world-readable - MEDIUM

| Field | Assessment |
| --- | --- |
| Description | The Mattermost configuration file at `/opt/mattermost/config/config.json` was readable by the `maildeliverer` account. The file contained the MySQL data source string including credentials for the `mmuser` database account in plaintext: `mmuser:Crack_The_MM_Admin_PW`. This allowed the contents of the Mattermost database to be read, including the password hash for the root account. |
| Prerequisites | Local shell access as any user that can read `/opt/mattermost/config/config.json`. |
| Impact | Read access to the entire Mattermost database via the `mmuser` account. The root bcrypt hash was extracted and subsequently cracked. |
| Affected system | delivery.htb - `/opt/mattermost/config/config.json` |
| CVSS 3.1 | **5.5** (Medium) AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| CWE | CWE-732: Incorrect Permission Assignment for Critical Resource |

### Steps to reproduce

1. Obtain a shell as `maildeliverer` via F-02.
2. Read the configuration file: `cat /opt/mattermost/config/config.json`.
3. Extract the `SqlSettings.DataSource` value to obtain the MySQL credentials.
4. Connect to MySQL: `mysql -u mmuser -p` and query the Users table.

### Evidence

```
cat /opt/mattermost/config/config.json

"SqlSettings": {
    "DataSource": "mmuser:Crack_The_MM_Admin_PW@tcp(127.0.0.1:3306)/mattermost?..."
}

mysql -u mmuser -p
use mattermost;
SELECT Username, Password FROM Users WHERE Username='root';

root | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO
```

Evidence E-03. MySQL credentials read from config.json by the low-privilege maildeliverer account. Root bcrypt hash extracted from the Mattermost Users table.

### Remediation

Set the permissions on `/opt/mattermost/config/config.json` so that only the Mattermost service account can read it (`chmod 600`, owned by the Mattermost service user). The `maildeliverer` account and any other non-Mattermost accounts should have no read access to the file or its parent directory.

### Verification

Confirm that `maildeliverer` cannot read `/opt/mattermost/config/config.json`. Verify that the Mattermost service account is a dedicated account with no interactive login and no membership in groups that would grant broader filesystem access.

## 4.4 Password Reuse and Weak Password Derivation Leads to Root

### F-04   System root password - bcrypt hash cracked via rule attack - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | The system root password was a variant of the phrase `PleaseSubscribe!`, derived by appending common numeric characters. The same derivation pattern was disclosed by root in a Mattermost channel post (F-02). The bcrypt hash extracted from the Mattermost database (F-03) was cracked in under one second using John the Ripper with the `best64` rule set seeded with the base phrase. The cracked password authenticated directly as system root via `su`, indicating that the Mattermost admin account and the system root account shared the same derived password. |
| Prerequisites | The bcrypt hash from F-03 and the base phrase hint from F-02. |
| Impact | Full root compromise. All files, accounts, services and network connections on the host are exposed. |
| Affected system | delivery.htb - system root account |
| CVSS 3.1 | **7.8** (Critical) AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| CWE | CWE-521: Weak Password Requirements |

### Steps to reproduce

1. Save the bcrypt hash from F-03 to a file: `echo '$2a$10$...' > root.hash`
2. Create a one-word wordlist with the base phrase: `echo 'PleaseSubscribe!' > base.txt`
3. Run John with the best64 rule: `john --wordlist=base.txt --rules=best64 root.hash`
4. Use the cracked password to authenticate as root: `su root`

### Evidence

```
echo '$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO' > root.hash
echo 'PleaseSubscribe!' > base.txt
john --wordlist=base.txt --rules=best64 root.hash

Loaded 1 password hash (bcrypt [Blowfish 32/64 X2])
PleaseSubscribe!21   (?)
1g 0:00:00:00 DONE

# su to root:
maildeliverer@Delivery:~$ su root
Password: PleaseSubscribe!21
root@Delivery:~# cat /root/root.txt
[redacted]
```

Evidence E-04. bcrypt hash cracked in under one second using a rule attack seeded from the hint disclosed in F-02. su authentication as root confirmed with the cracked password. Flag value redacted.

### Remediation

Set a unique, randomly generated password for the system root account that has no relationship to any application account or shared phrase. Enforce a password policy that prohibits predictable derivation patterns. Rotate all account passwords that may share the same base phrase. The Mattermost admin password should also be rotated to a value with no connection to any system account.

### Verification

Confirm that the system root password has been rotated to a value with no connection to any application account or known phrase. Verify that the Mattermost admin account password has also been rotated. Run a rule-based crack attempt against all extracted hashes using common base words to confirm the new passwords are not susceptible to the same attack.

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Rotate system root password and all application account passwords to unique, high-entropy values with no shared derivation. | F-04 |
| Immediate | Remove plaintext credentials from all Mattermost channels. Review full channel history. | F-02 |
| High | Restrict Mattermost config.json to the service account only (chmod 600). | F-03 |
| High | Segregate the helpdesk email domain from Mattermost verification. Require admin approval for new Mattermost accounts. | F-01 |
No remediation retest is documented. Each finding includes verification criteria for closure.

### 5.2 Test artefacts

| Location | Purpose | Removal status |
| --- | --- | --- |
| root.hash, base.txt on attacker machine | bcrypt cracking | Not verified |

### 5.3 Evidence and limitations

Evidence blocks are sourced from the [Delivery assessment walkthrough](delivery-htb.md) . Flag values, attacker IP addresses and the cracked account password are omitted from all evidence. The assessment did not include a review of the Mattermost application source code or the osTicket installation configuration beyond what was observed during testing.

### 5.4 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough section 2.1: osTicket ticket creation and Mattermost verification link |
| E-02 | Walkthrough section 2.2: Mattermost Internal channel credential disclosure and SSH foothold |
| E-03 | Walkthrough sections 3.2 and 3.4: config.json read and MySQL hash extraction |
| E-04 | Walkthrough sections 3.5 and 3.6: John rule-based crack and su to root |
