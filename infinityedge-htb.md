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
