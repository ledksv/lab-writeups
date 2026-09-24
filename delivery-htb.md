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
