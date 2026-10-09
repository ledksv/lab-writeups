# Window's Infinity Edge

**Platform:** HackTheBox
**OS:** Windows
**Type:** Forensics Challenge
**Tags:** Forensics, Traffic Analysis, Log Analysis, Incident Response, DFIR
**Date:** 2026-05-09

APT investigation challenge. AES-encrypted C2 traffic in a PCAP gets decrypted to identify an ASPX webshell. The .NET implant binary is reconstructed from network artefacts.

## 1. Scenario

The challenge presented a realistic incident response scenario. A motivated APT group had breached a company and deployed custom tooling across the environment. Implants were identified and supposedly cleaned by an advanced AV. One server appeared clean on the surface, but it was still generating suspicious outbound traffic.

Given: A PCAP capture of the suspicious traffic from the server. No running system. Pure artefact analysis.

## 2. PCAP Analysis

Opened the PCAP in Wireshark and started working through the traffic. The server was making outbound connections that looked like C2 communication: structured, periodic, and clearly not normal user activity. Used tshark to extract the raw data streams for closer inspection and started identifying the pattern of requests and responses.

Key finding: The traffic was encrypted, not plaintext C2. The challenge wasn't just reading the packets, it was recovering what was inside them.

## 3. Traffic Decryption

The C2 traffic was AES-encrypted. Had to extract the key material embedded in the PCAP, then write a Python script to decrypt the captured payloads and recover the actual commands and responses being sent. Working through the encryption layer was the most time-consuming part. Once decrypted, the full picture of what the implant was doing became clear.

## 4. Webshell and Binary Reconstruction

Inside the decrypted traffic there was a C# `.aspx` webshell that had been used for initial access and remote command execution. The traffic also contained encrypted byte arrays that turned out to be an embedded executable. Reassembled the binary, then decompiled it with ILSpy to analyse the full .NET implant. This made clear exactly what the APT had deployed and how it was operating.

**Result:** Flag retrieved. Full implant recovered and understood.

## 5. Reflection

This challenge strengthened skills in forensic investigation, traffic analysis, log analysis, incident response, and structured problem-solving. Good exercise in patience, attention to detail, and following the evidence wherever it led.

---

## Penetration Test Report

**Target:** APT intrusion - Windows server
**Address:** HackTheBox Forensics Challenge
**Assessment type:** Digital forensics & incident response - network artefact analysis
**Investigation date:** 9 May 2026
**Investigation date:** 9 May 2026
**Environment:** HackTheBox laboratory challenge - Windows - Forensics / DFIR
**Prepared by:** Ledion Mujaj
**Reference:** 01 / 10

---

## 1. Investigation Overview

### Scenario

A motivated APT group had breached a company and deployed custom tooling across the environment. The implants were identified and reportedly cleaned by an advanced AV solution. One Windows server continued generating suspicious outbound traffic despite appearing clean. This investigation was tasked with determining what remained on the system and reconstructing the full scope of the intrusion.
No live system access was available. The investigation was conducted entirely on static artefacts: a single PCAP capture of the suspicious outbound traffic from the affected server.

### Summary of findings

Analysis confirmed that a persistent implant was still active on the server. The outbound traffic was encrypted C2 communication. AES key material embedded in the PCAP was recovered, enabling full decryption of the captured traffic. The decrypted stream revealed a C# ASPX webshell that had been used for initial access, and encrypted byte arrays that were reassembled into a complete .NET implant binary. Decompilation confirmed the implant's full functionality.
Four artefacts were documented: the active C2 communication channel itself, the encryption scheme used to protect it, the ASPX webshell, and the .NET implant binary. Each is described in a dedicated finding section.

### Key conclusions

1. The AV cleanup was incomplete: the implant survived and maintained an active C2 channel.
2. Custom AES encryption concealed the C2 traffic from signature-based detection.
3. The webshell and implant represent distinct persistence mechanisms; both must be identified and removed.
4. The implant's capabilities, recovered through decompilation, define the full scope of attacker access during the period of the capture.

### Investigator's note

This challenge was a pure artefact analysis exercise. All conclusions are drawn from the PCAP capture alone. No system logs, memory dumps or filesystem images were available. Findings represent the maximum that could be established from the available evidence.

## 2. Artefact Scope and Analysis Methodology

### 2.1 Artefacts provided

| Artefact | Description |
| --- | --- |
| network_capture.pcap | PCAP recording suspicious outbound traffic from the affected Windows server. Contains encrypted C2 communication and embedded key material. |

### 2.2 Tools used

| Tool | Purpose |
| --- | --- |
| Wireshark | Initial PCAP inspection; protocol identification; stream isolation |
| tshark | Bulk stream extraction; scripted filtering of C2 sessions |
| Python / PyCryptodome | AES key extraction from PCAP; traffic decryption script |
| ILSpy | .NET assembly decompilation; implant capability analysis |

### 2.3 Analysis methodology

Analysis proceeded in four stages. First, the PCAP was opened in Wireshark and the traffic pattern characterised: the server was making structured, periodic outbound connections consistent with C2 beacon behaviour rather than user-initiated activity.
Second, tshark was used to extract the raw data streams for each C2 session. The streams were identified as encrypted rather than plaintext, requiring key recovery before content analysis.
Third, AES key material embedded in the PCAP was identified and extracted. A Python decryption script was written to process each encrypted stream and recover the plaintext payloads.
Fourth, the decrypted content was analysed. A C# ASPX webshell and encrypted byte arrays representing an executable were recovered. The byte arrays were reassembled into a .NET binary and decompiled with ILSpy.

### 2.4 Finding classification

Findings in this report document what was discovered during the investigation rather than attacker-controlled vulnerabilities in the traditional sense. Each finding describes an artefact or technique identified in the evidence.
| Classification | Meaning in this context |
| --- | --- |
| Confirmed | Directly evidenced in the PCAP or recovered artefacts. |
| Assessed | Conclusion drawn from available evidence with high confidence; direct artefact not recovered. |

## 3. Timeline and Results

### 3.1 Findings summary

| Reference | Finding | Classification | Page |
| --- | --- | --- | --- |
| [F-01](#f-01) | Active C2 communications identified in network capture | **Confirmed** | 6 |
| [F-02](#f-02) | AES-encrypted command and control traffic | **Confirmed** | 7 |
| [F-03](#f-03) | C# ASPX webshell recovered from decrypted traffic | **Confirmed** | 8 |
| [F-04](#f-04) | Embedded .NET implant binary reconstructed | **Confirmed** | 9 |

### 3.2 Reconstructed attack timeline

| Stage | Technique | Evidence |
| --- | --- | --- |
| Initial access | C# ASPX webshell deployed to IIS server; used for remote command execution. | Webshell source recovered from decrypted C2 traffic (F-03) |
| Implant delivery | Encrypted .NET binary transmitted over C2 channel; byte arrays reassembled and executed in memory. | Binary recovered and decompiled (F-04) |
| C2 establishment | Implant established persistent AES-encrypted outbound beacon to attacker-controlled infrastructure. | Structured periodic connections in PCAP (F-01); encryption confirmed (F-02) |
| Cleanup attempt | AV identified and reportedly removed implants. Active C2 traffic in capture indicates incomplete cleanup. | Ongoing beacon activity in PCAP after assumed cleanup |

### 3.3 Significance of incomplete cleanup

The continued outbound C2 traffic after the AV remediation is the central finding of this investigation. It indicates either that the implant survived on disk in a location the AV did not scan, that it survived in a fileless or memory-resident form, or that a secondary persistence mechanism was not identified. The available evidence does not distinguish between these possibilities; a memory image and filesystem artefacts would be required to make that determination.

## 4.1 Active C2 Communications Identified in Network Capture

### F-01   Persistent outbound beacon activity - CONFIRMED

| Field | Assessment |
| --- | --- |
| Description | The PCAP capture contains structured, periodic outbound connections from the affected Windows server to an external IP address. The traffic pattern - fixed-interval beaconing, consistent request sizes and structured response patterns - is consistent with command and control communication rather than normal user or application activity. |
| Significance | The activity post-dates the assumed AV cleanup, confirming that the implant was not fully removed. The server was actively maintaining contact with attacker-controlled infrastructure at the time of capture. |
| Technique | Periodic HTTP-based beacon; encrypted payloads (see F-02). ATT&CK T1071.001: Application Layer Protocol - Web Protocols. |
| Artefact | Network capture (PCAP) Outbound connections to external attacker-controlled IP |

### Analysis steps

1. Open `network_capture.pcap` in Wireshark and review the conversation list to identify external destinations.
2. Filter for outbound connections from the affected server's IP and observe periodic, structured requests at regular intervals.
3. Use tshark to extract individual TCP streams and compare request structure across sessions for uniformity consistent with automated beaconing.
4. Confirm the traffic pattern is not attributable to known application behaviour or user activity.

### Evidence

```
# Wireshark: filter for outbound connections from the server
# Repeated structured requests at regular intervals visible in packet timeline

# tshark stream extraction
tshark -r capture.pcap -z follow,tcp,ascii,<stream_id>

# Pattern observed:
# - Fixed beacon interval (consistent jitter)
# - Uniform request structure on each connection
# - Encrypted binary payload in POST body
# - Server responds with encrypted data

# Characteristic of automated implant beacon, not user traffic
```

Evidence E-01. Traffic pattern analysis from Wireshark and tshark. Specific timestamps, destination IP and stream contents withheld from this summary; full detail in the walkthrough record.

### Recommendations

Block the identified C2 destination IP at the network perimeter and on the host firewall. Collect a full memory image from the affected server to identify any in-memory implant that may have survived the AV cleanup. Isolate the server from the network until the persistence mechanism is fully identified and removed.

### Verification

Monitor outbound connections from the affected server after remediation. Confirm no further beacon traffic is observed to known or unknown external addresses. Conduct a full endpoint detection scan with updated signatures and memory analysis tooling.

## 4.2 AES-Encrypted Command and Control Traffic

### F-02   Custom AES encryption scheme with embedded key material - CONFIRMED

| Field | Assessment |
| --- | --- |
| Description | The C2 traffic identified in F-01 is encrypted using AES. The encryption scheme is custom-implemented by the APT tooling rather than relying on TLS. Key material required to decrypt the traffic was embedded within the PCAP itself - likely transmitted during an initial handshake or key exchange phase. Recovery of the key material enabled full decryption of all captured C2 sessions. |
| Significance | The use of custom AES encryption is a deliberate evasion technique (ATT&CK T1573.001: Encrypted Channel - Symmetric Cryptography). It prevents passive network inspection from revealing C2 commands and responses, and causes the traffic to appear as unrecognised binary data to signature-based detection tools. |
| Technique | AES symmetric encryption; key material transmitted in-band at session initiation. ATT&CK T1573.001. |
| Artefact | Encrypted C2 streams in PCAP AES key material extracted from initial handshake session |

### Analysis steps

1. Extract the first TCP stream from the PCAP using tshark: `tshark -r capture.pcap -z follow,tcp,ascii,0` .
2. Inspect the initial bytes of the session for structured data consistent with a key exchange or handshake (fixed-length byte sequences at session start).
3. Identify the AES key and IV material embedded in the handshake bytes.
4. Write a Python decryption script using PyCryptodome to decrypt subsequent session payloads and verify the recovered plaintext is intelligible C2 traffic.

### Evidence

```
# tshark: extract initial session stream containing key exchange
tshark -r capture.pcap -z follow,tcp,ascii,0

# AES key material identified in first session bytes
# Key extracted and used to initialise Python AES decryption

from Crypto.Cipher import AES
import base64

key = <extracted_key_bytes>
cipher = AES.new(key, AES.MODE_CBC, iv=<extracted_iv>)

# Decrypt subsequent C2 session payloads
plaintext = cipher.decrypt(base64.b64decode(encrypted_payload))

# Full C2 command/response traffic recovered in plaintext
```

Evidence E-02. Decryption approach transcribed from assessment record. Actual key bytes and decrypted payload content omitted; full content available in the walkthrough record.

### Recommendations

Network monitoring should be configured to flag unexplained binary or base64-encoded outbound traffic, particularly to non-standard destinations. Deploy TLS inspection where operationally feasible to detect encrypted non-TLS traffic. Retain full PCAP captures from high-value servers for post-incident analysis.

### Verification

Confirm no further AES-encrypted beacon traffic from the affected server after remediation. Review network flow logs for connections with similar traffic volume and interval profiles to identify any additional compromised hosts.

## 4.3 C# ASPX Webshell Recovered from Decrypted Traffic

### F-03   Initial access webshell identified in C2 stream - CONFIRMED

| Field | Assessment |
| --- | --- |
| Description | Decryption of the C2 traffic (F-02) revealed a C# `.aspx` webshell within the recovered data stream. The webshell is consistent with initial access tooling used to establish remote command execution on the IIS server before the full implant was deployed. The webshell source code was recovered in full from the decrypted traffic. |
| Significance | The webshell represents the initial access mechanism (ATT&CK T1505.003: Server Software Component - Web Shell). Its presence in the C2 traffic suggests it was either exfiltrated by the implant for documentation purposes or was transmitted as part of the deployment sequence. Regardless of current file status on disk, its recovery confirms the technique used for initial server access. |
| Technique | ASP.NET ASPX webshell deployed to IIS for remote command execution. ATT&CK T1505.003; T1059.001 (Command and Scripting Interpreter - PowerShell / .NET). |
| Artefact | C# .aspx webshell source recovered from decrypted C2 stream IIS web server on affected Windows host |

### Analysis steps

1. Apply the AES decryption script from F-02 to each captured C2 session stream.
2. Inspect the decrypted payloads for readable ASCII or UTF-8 content; identify the session containing source code.
3. Extract the C# `.aspx` content from the decrypted stream and review its structure to confirm remote command execution functionality.
4. Note the webshell's request handling logic (POST parameter parsing, execution primitive) to establish the initial access technique.

### Evidence

```
# After decrypting C2 stream (F-02), content analysis reveals:
# - C# ASPX source code for a remote command execution webshell
# - Webshell accepts POST requests and executes commands server-side
# - Standard pattern: Process.Start() or similar .NET execution primitive

# Webshell characteristics:
# - Language: C# / ASP.NET
# - File type: .aspx
# - Functionality: Remote OS command execution via HTTP POST
# - Delivery: Transmitted over C2 channel (exact delivery method not determined from PCAP alone)

# Full webshell source recovered and analysed.
```

Evidence E-03. Webshell characteristics transcribed from assessment record. Full webshell source available in the walkthrough record; not reproduced here.

### Recommendations

Conduct a full filesystem search on the affected IIS server for `.aspx` files that were not part of the original application deployment. Review IIS access logs for requests matching the webshell's URL pattern. Implement file integrity monitoring on the IIS web root. Deploy a web application firewall with rules to detect and block webshell request patterns.

### Verification

Confirm the webshell file is not present on disk, or has been removed. Review IIS logs for historical POST requests to the identified path to determine the extent of its use. Confirm no additional webshells or server-side scripts were deployed alongside the recovered specimen.

## 4.4 Embedded .NET Implant Binary Reconstructed

### F-04   Custom APT .NET implant recovered and decompiled - CONFIRMED

| Field | Assessment |
| --- | --- |
| Description | The decrypted C2 traffic contained encrypted byte arrays that were identified as a segmented executable. The byte arrays were reassembled in the correct sequence, producing a valid .NET PE binary. The binary was decompiled using ILSpy, revealing a fully featured custom implant - the same tool responsible for the C2 beacon traffic observed throughout the capture. Decompilation confirmed the implant's full capability set, including the AES communication module, command dispatch logic and persistence mechanisms. |
| Significance | Recovery of the binary enabled complete understanding of the attacker's tooling. The implant is custom-developed, reducing the effectiveness of signature-based detection. Its capability set defines the full scope of attacker access during the capture period. ATT&CK T1027: Obfuscated Files or Information; T1059.001: Command and Scripting Interpreter; T1571: Non-Standard Port. |
| Technique | Segmented encrypted binary transmission; .NET PE assembly; ILSpy decompilation for capability analysis. |
| Artefact | Reconstructed .NET PE binary from decrypted C2 byte arrays Decompiled source via ILSpy |

### Analysis steps

1. Identify decrypted C2 sessions containing binary (non-ASCII) payloads after applying the decryption from F-02.
2. Extract the byte array chunks from each session and sort them by transmission sequence number.
3. Concatenate the sorted chunks and write the output to a file; verify the result is a valid PE binary using the `file` command.
4. Load the binary into ILSpy and decompile to recover the .NET source; confirm the AES communication module, command dispatch, and persistence logic match the observed beacon behaviour in F-01 and F-02.

### Evidence

```
# Decrypted C2 stream contains sequential encrypted byte array chunks
# Reassembly: concatenate chunks in order of transmission sequence number

with open("implant_bytes.bin", "wb") as f:
    for chunk in sorted_chunks:
        f.write(decrypt_aes(chunk))

# Verify: file command confirms PE32+ .NET assembly
file implant_bytes.bin
# implant_bytes.bin: PE32+ executable (DLL) Intel 80-64, Mono/.Net assembly

# Decompile with ILSpy
# -> AES C2 communication module confirmed
# -> Command dispatch: shell exec, file I/O, process injection capability
# -> Beacon interval and jitter settings match observed PCAP traffic pattern
# -> Encryption key derivation routine matches key material in PCAP
```

Evidence E-04. Reconstruction approach and ILSpy findings transcribed from assessment record. Full decompiled source available in the walkthrough record.

### Recommendations

Submit the recovered binary to threat intelligence platforms and share indicators of compromise (file hash, C2 IP, network signature) with the security community. Use the decompiled source to develop YARA rules targeting unique strings or code patterns in the implant. Conduct a full memory scan on all servers for in-memory variants of this implant using strings and patterns derived from the decompiled code.

### Verification

Confirm no variant of the recovered binary is present on disk or in memory on the affected server or any adjacent host. Validate that YARA rules derived from the implant's code produce positive matches on the recovered sample and are deployed to the endpoint detection platform.

## 5. Conclusions and Recommendations

### 5.1 Investigation conclusions

The investigation confirms that the affected Windows server was compromised by a custom APT toolset. The AV cleanup was incomplete: the implant survived and maintained an active AES-encrypted C2 channel to external attacker infrastructure at the time of capture. Four artefacts were identified and documented from the PCAP alone.
The attack sequence moved from ASPX webshell deployment for initial command execution, through in-memory implant installation, to a persistent encrypted beacon. The custom nature of the tooling - particularly the AES communication layer - was designed to evade detection. The incomplete cleanup is consistent with a fileless or memory-resident persistence mechanism that the AV did not address.

### 5.2 Recommended remediation actions

| Priority | Action | Reference |
| --- | --- | --- |
| Immediate | Isolate affected server; block C2 destination IP at perimeter and host firewall. | F-01 |
| Immediate | Collect memory image and conduct full memory forensics to identify in-memory persistence. | F-01, F-04 |
| High | Search IIS web root for ASPX webshells not part of original deployment; review IIS access logs. | F-03 |
| High | Deploy YARA rules derived from recovered implant binary to all endpoints. | F-04 |
| Medium | Implement network monitoring for binary/encrypted outbound traffic to non-approved destinations. | F-02 |

### 5.3 Artefact index

| Reference | Artefact | Recovery method |
| --- | --- | --- |
| E-01 | C2 beacon traffic pattern | Wireshark / tshark PCAP analysis |
| E-02 | AES encryption scheme and key material | tshark stream extraction; Python decryption script |
| E-03 | C# ASPX webshell source | Recovered from decrypted C2 traffic stream |
| E-04 | .NET implant binary | Reassembled from decrypted byte arrays; decompiled with ILSpy |

### 5.4 Limitations

This investigation was conducted on a single PCAP artefact. No filesystem image, memory dump, Windows Event Logs or registry hives were available. Conclusions about persistence mechanism, initial delivery vector for the webshell, and extent of data access are therefore assessed rather than confirmed from direct artefacts. A complete investigation would require full disk and memory images from the affected host.
Evidence blocks are sourced from the [Window's Infinity Edge investigation walkthrough](infinityedge-htb.html) .
