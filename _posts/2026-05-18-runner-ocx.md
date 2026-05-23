---
layout: post
title: "Part 1: Runner.ocx Malware Analysis"
date: 2026-05-18
categories: [malware, RAT, C2]
tags: [capa, floss, die, pe-stats, pe-analysis, ghidra, x64dbg]
---
## Introduction
In this analysis, we dive deep into Aa full featured RAT with credential harvesting and lateral movement capability. Our workflow will look something like this:

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



## FLOSS - String Analysis
FLOSS uses advanced static analysis techniques to automatically extract and deobfuscate all strings from malware binaries. 

<img src="/assets/images/posts/2026-05-18-runner-ocx/floss-analysis-loading.png" alt="floss-analysis-loading" width="800" style="display:block; margin-left:0;">

Using FLOSS, we uncover some intriguing strings.

- DllInstall: Koki=
- Koki cmd=[
- regsvr32 /s /i "
- regsvr32 /s "
- AgentThread

FLOSS also reveals a few other malware capabilities.
- Schedule Task - create, run, delete
- Registry Manipulation - create, set, delete, query
- SMB lateral movement via NTLM
- Clipboard Access
- Microphone recording

<img src="/assets/images/posts/2026-05-18-runner-ocx/floss-dllinstall.png" alt="floss-dllinstall" width="400" style="display:block !important; margin-left:0 !important;">

We also come across what appears to be a conditional check. Dllinstall is referenced once again. It should serve as a good investigation point in our Ghidra analysis later. Dllinstall looks to initialize a thread named AgentThread. Looking at "CreateThread Failed," we could surmise AgentThread won't start if the filename check does not pass.

## DIE - Detect it Easy

Using Detect-it-Easy, we can determine if our malware is packed. By examining levels of entropy or randomness, we can determine whether the malware has been packed.

<img src="/assets/images/posts/2026-05-18-runner-ocx/die-entropy.png" alt="die-entropy" width="400" style="display:block !important; margin-left:0 !important;">

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

While walking through the functions in Ghidra, I found a function for used for C2 communication. The function looks to be related to command dispatch. Jumping into the function reveals a host of encrypted commands and functions related to the C2 operation. While a majority of the commands are encrypted and look to be decrypted at runtime, but a few were in plaintext. I've listed them below.

| Tactic | Technique | Command |
|--------|-----------|---------|
| `Privilege Escalation` | `T1134 - Access Token Manipulation` | `token_run` |
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

<img src="/assets/images/posts/2026-05-18-runner-ocx/decryption-function.png" alt="decryption-function" width="400">

In the above screenshot, you can see the encrypted command named &DAT_2581afcc0. I thought if we set a breakpoint at the decryption function FUN_25819fe10 in x64dbg, I might be able to view the C2 commands decrypt in realtime. 

# Dynamic Analysis

It's time to have some fun and start playing with the malware in real time. Let's dive into executing the code in our test lab.

## x64dbg - Dllinstall

So far in our analysis, we've seen the exported function DllInstall appear a few times. Let's look into this function. 

<img src="/assets/images/posts/2026-05-18-runner-ocx/1.png" alt="x64dbg reveals proper filename" width="800">

Using the symbols tab in x64dbg, I set a breakpoint on DllInstall and run the program. I land on the DllInstall API call and proceed to step through the code. While stepping through the code, the filename appears in the stack. We have identified the correct filename `runner.ocx`. I should note that I had originally named the malware `dr.dll.exe` when I initially downloaded it from `MalwareBazaar`. 


# FakeNet-NG - Network Analysis

Fakenet-NG is a tool that allows you to intercept and redirect all or specific network traffic while simulating legitimate network services. I used FakeNet-NG for dynamic network analysis. After renaming dr-dll.exe to runner.ocx, I execute the malware and notice the AgentThread started! The filename check passed and it ran it's initialization code.

<img src="/assets/images/posts/2026-05-18-runner-ocx/fakenet-ng.png" alt="fakenet-ng" width="800">

Note that earlier in our analysis, we found that the DllInstall export API contained a filename check. The check is required to pass in order to execute AgentThread. Further analysis in Ghidra revealed to us AgentThread's purpose.

AgentThread Functionality
1. WSAStartup
2. DNS lookup for xtrafftrck[.]net
3. TCP connection to port 3000
4. WebSocket handshake
5. C2 communication

## x64dbg - ws2_32connect

In an effort to get better at x64dbg and reverse engineering, I set off to find where in the malware the C2 and port were called in memory. To accomplish this task, I set a breakpoint on ws2_32connect in x64dbg. Once I landed on the breakpoint, I stepped through the code until I was able to find the C2 domain. VirusTotal confirms xtrafftrck[.]net is still live and malicious with 20/93 vendors flagging.

<img src="/assets/images/posts/2026-05-18-runner-ocx/C2-domain.png" alt="C2 Domain" width="800">

So we have the domain, now let's find the port number it uses to dial out. I dump RDX to memory to reveal two bytes with a value of 0xBB8 which translates to 3,000 or port 3000. 

<img src="/assets/images/posts/2026-05-18-runner-ocx/port-reveal.png" alt="x64dbg reveals C2 port" width="800">

When you see ws2_32.dll being called for a network connection, the likely function is getaddrinfo or connect. The code snippet below maps the function inputs to windows registers. 

```
getaddrinfo(hostname, port_or_service, hints, result)
In x64 Windows calling convention those map to:
    - RCX = hostname > xtrafftrck[.]net
    - RDX = port/service string > points to "3000" as a string
 ```       


# Calculating Relative Virtual Address (RVA)
We noted in Ghidra that we suspect the command dispatch function decrypts it's windows commands during runtime. To test this theory, we need to set a breakpoint in x64dbg on the decryption function 25819fE10. However, Ghidra addresses do not directly translate to runtime addresses in x64dbg, especially if ASLR is enabled. We'll need the relative virtual address in x64dbg to set a proper breakpoint.

A technique I am learning is how to calculate the relative virtual address. Below is my process for calculating RVA. We use the decryption function address and subtract it from the base address in Ghidra. The result is an offset that we will use to calculate the RVA in x64dbg.

In x64dbg, we load up our malware and open memory map. We locate runner.ocx and note the image base. We then add the Ghidra offset + x64dbg image base address. The result is the RVA of the decryption function. 
 
## Ghidra + x64dbg Image Base
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

## Python Custom C2 

The next idea is to create a C2 responder in Python. I originally used FakeNet-NG to get the malware to make a connection, but the malware required a response from the C2 to decrypt the commands. The command only decrypted at runtime when specifically called. Perhaps we can intercept the decryption using a custom C2 python responder.

I created a responder python script for the C2 domain listening on port 3000. This is very cool as we're able to interact with the malicious executable as if we were the C2 server! To get this to work properly, I had to edit the windows host file C:\windows\system32\drivers\etc\hosts and add 127.0.0.1 xtrafftrck[.]net.

<img src="/assets/images/posts/2026-05-18-runner-ocx/python-script.png" alt="python-script" width="400">

## Interacting with the Malware via Custom C2 Responder

With the hosts file redirecting, I fired up a custom Python WebSocket server to simulate the `Chopi` C2 dashboard. The malware connected on `/ws/agent` exactly as the FLOSS strings predicted.

<img src="/assets/images/posts/2026-05-18-runner-ocx/c2-success-2.png" alt="c2-success-" width="800">

Sending commands confirmed the C2 protocol uses JSON with a `type` field. The malware responds with a matching `<command>_result` type. Three commands returned live responses.

`chrome_extract` returned:
```json
{"data":{"error":"OCX not found. Upload first."},"type":"chrome_result"}
```

The Chrome credential extraction requires `chromelevator.ocx` to be uploaded to the victim machine first via a `chrome_upload` command before extraction can proceed. This confirms the two stage Chrome harvesting workflow identified during static analysis.

`wpad_start` returned:
```json
{"data":{"error":"WPAD OCX not found. curl may have failed."},"type":"wpad_result"}
```

The WPAD poisoning capability follows the same pattern. `wpad_capture.ocx` must be staged on the victim machine before the operator can activate WPAD based NTLM credential capture.

`cdp_start` produced an another interesting result. Microsoft Edge launched on my machine before returning:
```json
{"data":{"error":"Chrome exited immediately with code 0. Path: C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe","success":false},"type":"cdp_start_result"}
```

`net_enumerate` produced the best response yet. The command enumerated my entire network. Wow!

```json
{"data":{"hosts":[{"domain":"WORKGROUP","fqdn":"JohnDesktop","hostname":"JOHNDESKTOP","ip":"10.0.0.1","mac":"08:00:27:a7:24:14","os":"","ports":[135,139,445,3389],"source":"enumerate"},{"domain":"","fqdn":"DESKTOP-VT730LL","hostname":"","ip":"10.0.0.2","mac":"08:00:ff:88:7b","os":"","ports":[135,139,445],"source":"enumerate"}]}}
```
It went through 4 phases of scanning. `arp` to discover additional hosts, `netbios` name resolution, `scanning` port scanning and `smb` enumeration. We also received hostnames, MAC addresses, IP addresses, open ports, workgroup membership, and RDP exposure. This serves as foundational data for a threat actor.

These responses confirm that operator tasking happens exclusively over the WebSocket connection using JSON commands.

## x64dbg - lg.txt 

During debugging, I came across an interesting file path in the stack.

<img src="/assets/images/posts/2026-05-18-runner-ocx/lg-zoomed.png" alt="lg.txt" width="400">

Let's examine `C:\Users\johnrAppData\Local\Temp\lg.txt`.

<img src="/assets/images/posts/2026-05-18-runner-ocx/lg-goldmine.png" alt="lg-goldmine" width="800">

Investigating the file reveals a goldmine of information. We can see strings similar to the ones FLOSS had provided to us during static analysis.

1. Koki cmd=[
2. AgentThread
3. DllInstall

Look closely at line 3, we can see the conditional parameter check `Found=YES`. We discussed the file name check earlier in our analysis. If the `Koki` and `Blat` parameters pass the check, `Agentthread` is started. 

What's more is we can see the C2 domain is contacted via `AgentThread` and is sending our `hostname`, `userID` and `local IP address`. The files purpose is to aide in threat actor in debugging the malware. The lg.txt file discovery has confirmed a few hypothesis's we established early on in our analysis. AgentThread is the C2 domain connection process. DllInstall is our malware entry point and Koki=[ is our command parameter check.

## Koki Check

The `Koki` cmd contains the full command line used to invoke the malware. The `tail` parameter extracts just the filename from that command line, in this case runner.ocx. 

<img src="/assets/images/posts/2026-05-18-runner-ocx/koki-string-search.png" alt="koki-string-search" width="800">

Setting a breakpoint on `DllInstall` and searching the current module for string `koki`. 

<img src="/assets/images/posts/2026-05-18-runner-ocx/koki-check-disembler.png" alt="koki-check" width="800">

# Conclusion
 We used static analysis to uncover as much information as we can before moving on to dynamic analysis. While this part may not be the most fun it certainly aides in better understanding the malware you're investigating. Later, we moved on to dynamic analysis where we executed the malware in a controlled environment. We discovered the C2 domain, port address and correct malware name in x64dbg. We then pivoted to developing a custom C2 responder in python that allowed us to interact with the malware in realtime.

In part 2 of the series, I dive into threat intelligence and aim to map out the malwares infrastructure. You can find the link [Part 2: Runner.ocx Mapping the Infrastructure](https://jryaniii.github.io/posts/runner-threat-intel/).

## IOCs

| Field | Value |
|-------|-------|
| File Name | `runner.ocx` |
| Internal Name | `runner.dll` |
| SHA256 | `9a2d714ddd5c48722c35df8a70e97f12d46bcde05dc79b7242a7e692bd346826` |
| MD5 | `9d6f7697c0fbea55d6bfb39642eb87df` |
| SHA1 | `2b57771989fc059bbef8f28fc0ca24eeae7e7863` |
| File Size | `3.83 MB` |
| File Type | `PE64 DLL` |
| Compile Time | `2026-05-01 08:56:47 UTC` |
| C2 Domain | `xtrafftrck[.]net` |
| C2 Port | `3000` |
| C2 Protocol | `WebSocket (ws://)` |
| C2 Endpoint | `/ws/agent` |
| Secondary Payload | `chromelevator.ocx` |
| Secondary Payload | `wpad_capture.ocx` |
| Debug Log | `C:\Users\UserID\Appdata\Local\Temp\lg.txt` |
| Check | `Koki=YES Blat=YES` |
| Compiler | `GCC 13 MinGW (cross-compiled on Linux)` |
| Embedded Library | `IXWebSocket` |
| Embedded Library | `mbed TLS 3.5.2` |
| Embedded Library | `libjpeg-turbo 3.1.90` |
| Embedded Library | `zlib 1.3.2` |

---

## References

- [VirusTotal](https://www.virustotal.com)
- [MalwareBazaar](https://bazaar.abuse.ch/)


---

Analysis performed: 2026-05-18 | Analyst: John Ryan