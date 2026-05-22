---
layout: post
title: "Part 1: Runner.ocx Malware Analysis"
date: 2026-05-18
categories: [malware, RAT, C2]
tags: [capa, floss, die, pe-stats, pe-analysis, ghidra, x64dbg]
---
## Introduction
In this analysis, we dive deep into C2 malware. Our workflow will look something like this:

1. `Static Analysis` using Capa, Floss, DIE, PEStats, Ghidra
2. `Dynamic Analysis` using x64dbg, FakeNet-NG, Custom Python C2

# Static Analysis

| Field         | Value |
|---------------|-------|
| File Name     | `runner.ocx` |
| SHA256        | `9a2d714ddd5c48722c35df8a70e97f12d46bcde05dc79b7242a7e692bd346826` |

## Capa - Capability Mapping
Capa is an open-source tool created by Mandiant's FLARE team that detects capabilities in executable files. 

<img src="/assets/images/posts/2026-05-18-runner-ocx/capa-analysis-loading.png" alt="capa-analysis-loading" width="800">

Initial analysis confirms the following: 

1. Confirmed XOR encoding, RC4, and AES capabilities.
2. Confirmed full active directory enumeration capability.
3. Proxy enumeration
4. Privilege escalation
5. Credential harvesting
6. Lateral movement and network enumeration.



## Floss - String Analysis
Floss uses advanced static analysis techniques to automatically extract and deobfuscate all strings from malware binaries. 

<img src="/assets/images/posts/2026-05-18-runner-ocx/floss-analysis-loading.png" alt="floss-analysis-loading" width="800" style="display:block; margin-left:0;">

Using floss, we uncover some intriguing strings.

- DllInstall: Koki=
- Koki cmd=[
- regsvr32 /s /i "
- regsvr32 /s "

We could put these strings together to form a command. 

```
regsvr32 /s /i koki=[],dllinstall
```

Floss also reveals a few other malware capabilities.
1. Schedule Task - create, run, delete
2. Registry Manipulation - create, set, delete, query
3. SMB lateral movement via NTLM
4. Clipboard Access
5. Microphone recording

<img src="/assets/images/posts/2026-05-18-runner-ocx/floss-dllinstall.png" alt="floss-dllinstall" width="400" style="display:block; margin-left:0;">

We also come across what appears to be a conditional check. Dllinstall is referenced once again. It should serve as a good investigation point in our Ghidra analysis later. Dllinstall looks to initialize a thread named AgentThread. Looking at "CreateThread Failed," we could summize AgentThread won't start if the filename check does not pass.

## DIE - Detect it Easy

Using Detect-it-Easy, we can determine if our malware is packed. By examining levels of entropy or randomness, we can determine whether the malware has been packed.

<img src="/assets/images/posts/2026-05-18-runner-ocx/die-entropy.png" alt="die-entropy" width="400" style="display:block; margin-left:0;">

The results are in! The malware has low entropy and is thus not packed. Lucky us!

## PEStats

PEStats is a custom tool built by SANs instructor Anoj Soni. This tool assists by providing binary compile timestamps, exports, packing, entry points and internal file name of the malware.

1. Compile timestamp is `2026-05-01 08:56:47 UTC`
2. `No Packing` confirmed
3. TLS callbacks 1 & 2 entry points `(0x257e91340, 0x257e91320)`
4. `Unsigned binary`
5. Three exports `(DllInstall, DllRegisterServer, DllUnregisterServer)`
6. Internal name is the binary name `(runner.dll)` not `runner.ocx`

The TLS callbacks are interesting. TLS callbacks execute before code. This section of the executable can be used for anti-debugging capability.


## Ghidra - Static Code Analysis

During this analysis, I took my first dive into Ghidra. Honestly, AI assisted pretty heavily. But, I feel if I keep at that approach eventually it will click. No one knows everything all at once. I was hesitant to take on Ghidra because the depth is so vast, but while I was plugging away I found the process quite enjoyable.

AI was really interested in the TLS portion in the beginning. It thought the malware C2 configuration was linked there. Eventually, it wound up being a dead end and we pivoted to the exported function DllInstall. I walked through the pseudo C code and found the malware required a few conditional checks to pass before running properly. The main check was the filename. Now, in hindsight a simple VirusTotal lookup would have told me the filename, but I chose the hard way and decided to debug the program. 

<img src="/assets/images/posts/2026-05-18-runner-ocx/1.png" alt="x64dbg reveals proper filename" width="800">

The first step was to calculate the RVA (Relative Virtual Address) for the DLLInstall function and set a breakpoint. Or, as it turns out, I could have just looked at the symbols tab and set a breakpoint there. I landed on the DllInstall API call in x64dbg and proceeded to step through the code. Alas, I found the required filename "runner.ocx." 

I should mention that if the malware was not correctly named the AgentThread function FUN_257ea2af0 would not start. This means the following would not occur:

## AgentThread Functionality
```
WSAStartup
DNS lookup for xtrafftrck[.]net
TCP connection to port 3000
WebSocket handshake
C2 communication
```
<img src="/assets/images/posts/2026-05-18-runner-ocx/fakenet-ng.png" alt="x64dbg reveals proper filename" width="800">

I used FakeNet-NG for dynamic network analysis. After renaming dr-dll.exe to runner.ocx, the AgentThread started! The filename check passed and it ran it's initialization code.

<img src="/assets/images/posts/2026-05-18-runner-ocx/C2-domain.png" alt="fakenet C2 activity" width="800">

In an effort to get better at x64dbg and reverse engineering, I set off to find where in the malware the C2 and port were called. To do this I set a breakpoint on ws2_32connect. Once I landed on the breakpoint, I stepped through the code until I was able to find the C2 domain. VirusTotal confirms xtrafftrck[.]net is still live and malicious with 20/93 vendors flagging.

<img src="/assets/images/posts/2026-05-18-runner-ocx/port-reveal.png" alt="x64dbg reveals C2 port" width="800">

I dumped RDX to memory to reveal 2 bytes with a value of 0xBB8 which translates to 3,000 or port 3000. When you see ws2_32.dll being called for a network connection, the likely function is getaddrinfo or connect. 

## Mapping Getaddrinfo API to Registers
```
getaddrinfo(hostname, port_or_service, hints, result)
In x64 Windows calling convention those map to:
    - RCX = hostname > xtrafftrck[.]net
    - RDX = port/service string > points to "3000" as a string
 ```       
At this point, I wanted to learn more about the C2 commands. Earlier in Ghidra, I found a function for C2 command dispatch and aptly renamed it to CommandDispatcher. A majority of the commands are encrypted and look to be decrypted at runtime, but a few were in plaintext. I've listed them below.

| Tactic | Technique | Command |
|--------|-----------|---------|
| `Privilege Escalation / Def. Evasion` | `T1134 - Access Token Manipulation` | `token_run` |
| `Credential Access` | `T1185 - Browser Session Hijacking` | `cdp_start` |
| `Credential Access` | `T1185 - Browser Session Hijacking` | `cdp_stop` |
| `Credential Access` | `T1185 - Browser Session Hijacking` | `cdp_send` |
| `Credential Access` | `T1557.001 - LLMNR/NBT-NS Poisoning` | `wpad_start` |
| `Credential Access` | `T1557.001 - LLMNR/NBT-NS Poisoning` | `wpad_stop` |
| `Credential Access` | `T1557.001 - LLMNR/NBT-NS Poisoning` | `wpad_hashes` |
| `Credential Access` | `T1539 - Steal Web Session Cookie` | `chrome_upload` |
| `Credential Access` | `T1555.003 - Credentials from Web Browsers` | `chrome_extract` |
| `Lateral Movement` | `T1021.002 - SMB/Windows Admin Shares` | `cred_logon` |
| `Lateral Movement / Execution` | `T1021.002 - SMB/Windows Admin Shares` | `cred_exec` |
| `Discovery` | `T1018 - Remote System Discovery` | `net_enumerate` |
| `Lateral Movement` | `T1550.002 - Pass the Hash` | `remote_logon` |
| `Discovery` | `T1033 - System Owner/User Discovery` | `whoami` |

<img src="/assets/images/posts/2026-05-18-runner-ocx/decryption-function.png" alt="decryption-function" width="400">

You can see the encrypted command named &DAT_2581afcc0 in the screenshot above. I thought if we set a breakpoint at the decryption function FUN_25819fe10 in x64dbg, I might be able to view the C2 commands decrypt in realtime. 

A technique I am learning is calculating the relative virtual address. Below is my process for calculating RVA. We use the decryption function address and subtract it from the base address in Ghidra. The result is an offset that we will use to calculate the RVA in x64dbg.

In x64dbg, we load up our malware and open memory map. We locate runner.ocx and note the image base. We then add the Ghidra offset + x64dbg image base address. The result is the RVA of the decryption function. 
 
# Calculating RVA (Ghidra + x64dbg)
The decryption function FUN_25819fe10 is called before every command executes in the CommandDispatch function.

<img src="/assets/images/posts/2026-05-18-runner-ocx/ghidra-imagebase.png" alt="ghidra imagebase" width="400">



<img src="/assets/images/posts/2026-05-18-runner-ocx/x64-imagebase.png" alt="x64-imagebase" width="400">

The two screenshots above highlight the base images for Ghidra and x64dbg. Ghidra base image is 257e90000. Let's calculate the RVA so we can breakpoint on this function in x64dbg.

## Ghidra Offset Calculation

```
Decryption Function
25819fE10

Image Base
257e90000

Offset
(25819fe10 - 257e90000) = 30fe10
```

## x64dbg Relative Virtual Address Calculation

```
x64dbg runner.ocx image base
7FFFA5E30000

runner.ocx image base + Ghidra offset = RVA
(7FFFA5E30000 + 30FE10) = 7FFFA6130E10
```

Unfortunately, setting the breakpoint wasn't the answer. Dynamic debugging revealed to us that the commands were decrypted only when specifically called on from the C2 server.

The next idea was to create a C2 responder in Python. I originally used FakeNet-NG to get the malware to make a connection, but the malware required a response from the C2 to decrypt the commands. The command only decrypted at runtime when specifically called.

I created a responder python script for the C2 domain on port 3000. This is very cool as we're able to interact with the malicious executable as if we were the C2 server! To get this to work properly, I had to edit the windows host file C:\windows\system32\drivers\etc\hosts and add 127.0.0.1 xtrafftrck[.]net.

<img src="/assets/images/posts/2026-05-18-runner-ocx/python-c2-script.png" alt="python-c2-script" width="800">

<img src="/assets/images/posts/2026-05-18-runner-ocx/c2-domain-response.png" alt="c2-domain-response" width="800">
    
Above you can see the python script in action. It took some time to get here but I finally got a C2 RECV response. The C2 server expected "type" as a field for the command. Without proper field name, the malware would not respond. It took a lot of trial and error. This screenshot makes it look easy.

While we were able to get the malware to respond to fake C2 python server, the syntax wasn't quite there. You can see in the screenshot it replied with an error. At this point, I decided to stop tinkering and gave up on achieving the proper syntax. In the end, we created a working C2 responder that triggered a real response from the malware. Very cool.

<img src="/assets/images/posts/2026-05-18-runner-ocx/lg-debug.png" alt="lg-debug" width="800">

During debugging, I found the software dropped this file in AppData. It's not keylogger information. It's debugging information related to the malicious software C:\Users\userID\AppData\Local\Temp\lg.txt. I first thought this was the keylogger output, but it turned out to be debugging information from the malware.

# Conclusion
I must admit that this was quite the experience. Developing a C2 responder was the highlight of the investigation. There are many malware analysis avenues I did not pursue. Overtime, I'll look to build upon my report more thoroughly. For example, MITRE, Network IOCs, Floss & Capa findings as well the extent of the malware capability.

In part 2 of the series, I dive into threat intelligence. You can find the link [Part 2: Runner.ocx Mapping the Infrastructure](https://jryaniii.github.io/posts/runner-threat-intel/).

## IOCs

| Field         | Value |
|---------------|-------|
| File Name     | `runner.ocx` |
| SHA256        | `9a2d714ddd5c48722c35df8a70e97f12d46bcde05dc79b7242a7e692bd346826` |
| File Size     | `3.83 MB` |
| File Type     | `PE64` |
| Compile Time  | `2026-05-01 08:56:47 UTC` |
| C2 Domain | `xtrafftrck[.]net` |
| C2 Port | `3000`|
| C2 Protocol | `Web Socket (ws:// and wss://)` |

---

## References

- [VirusTotal](https://www.virustotal.com)
- [MalwareBazaar](https://bazaar.abuse.ch/)


---

Analysis performed: 2026-05-18 | Analyst: John Ryan