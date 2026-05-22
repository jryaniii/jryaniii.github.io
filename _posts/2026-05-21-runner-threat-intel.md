---
layout: post
title: "Part 2: Runner.ocx Threat Intelligence"
date: 2026-05-21
categories: [malware, threat intelligence,]
tags: [virustotal, shodan, censys, threafox]
---
## Overview

I performed threat intelligence on the runner.ocx sample. Using various threat intel web platforms, I uncovered what appears to be a dedicated threat campaign.

---

## Malware Summary

| Field | Value |
|-------|-------|
| Malware Filename Name | `runner.ocx` |
| SHA256 | `9a2d714ddd5c48722c35df8a70e97f12d46bcde05dc79b7242a7e692bd346826` |
| C2 Domain | `xtrafftrck[.]net` |
| C2 Port | `3000` |

---
## Getting Started - Virus Total
Virus Total is a great way to start. It reveals a gold mine of information like domain reputation, related IP addresses, https certificate details, passive DNS & community notes.

Here's what we discovered in our initial Virus Total analysis on the C2 domain.

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

## Virus Total - C2 IP Pivot
The front page is painted red! With 16 out of 91 security vendors flagging the domain as malicious. Digging into the details tab, we find a public IP address associated with our malware's C2. 

We've also uncovered interesting tags assocaited with this IP. The tags were submitted by a community researcher named `JaffaCakes118`. The researcher attributes `Chopi` as a campaign tag. We'll look into this tag later in the report.

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

Before diving into our newly discovered domains, let's lookup the IP 70.34.205[.]43 in Shodan. Shodan is search engine for the internet of everything. If it's online, it's in Shodan. After plugging in the IP, we're presented with two domains screenly[.]cam and vulltrusercontent[.]com.
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
Shodan provided a wealth of information. It revealed open port 3000, running a monitoring software named `Chopi Monitoring Dashboard`, which I believe is used for C2 management. The name Chopi ties back to the campaign tag identified by the community researcher on VirusTotal. Port 4000 is an interesting find, possibly expecting a specific key, header, or handshake before responding, as it currently returns a Bad Request error. Port 22 is standard for Vultr hosted infrastructure.

The HTTPS certificate thumbprint is an interesting artifact. Let's see what it reveals to us. We'll use another tool called Censys to investigate the certificate.

## Censys - Screenly HTTPs Certificate Thumbprint 
Earlier in VirusTotal, we identified several domains associated with the C2 IP address. Inputting the HTTPS certificate thumbprint `f6be95351f72b24e1232c138f426aa612864696f` into Censys reveals a significant finding. The threat actor reused the screenly[.]cam certificate for aurekh[.]com, confirming shared operator ownership. As noted in our VirusTotal table, aurekh[.]com was already associated with our C2 IP address.

I searched Censys for the other domains Virus Total provided but found no certificate reuse. between them.

## Virus Total - Screenly
Let's go back to Virus Total and review screenly[.]cam. This time let's look at the community notes provided by `JaffaCakes118`. He references the tags seen below. They look oddly similar to the tags we saw on our C2 domain earlier.

Tags: `chopi` `ClickFix` `ixwebsocket` `ocx` `WebDav` `Unknown_malware`

## Google

We've seen similar tags now between our C2 domain and screenly[.]cam. Let's do a web search on Google for the `Chopi` campaign tag. Pivoting to Google, I lookup `malware chopi` and I'm presented with a link to Threatfox.

<img src="/assets/images/posts/2026-05-21-runner-threat-intel/figure1-threatfox.png" alt="lg-debug" width="800">

Check out the results! Threat researcher `Lenny_3BO` has already submitted his own findings for the `Chopi` malware campaign. Comparing his submissions against our malware sample reveals overlapping malicious domains and IPs. Very cool!

## Attack Chain

WebDav is a new concept I've come to learn in my analysis. The attack chain typically starts with a phishing email carrying a URL file or an LNK. When executed, Windows silently mounts the remote WebDAV share and the payload is loaded directly into memory, bypassing the local filesystem entirely. No file write, no Mark of the Web (MotW), no SmartScreen prompt. That last part is the real win for the attacker.

The full delivery chain was reconstructed from ThreatFox IOC submissions and infrastructure analysis.

```
Victim receives LNK file (WebDAV delivered)

LNK executes ClickFix lure via screenly[.]cam/s/

Victim shown fake page, instructed to paste command

Command runs regsvr32 pulling updater.ocx from xtrafftrck[.]net/files/

DllInstall validates internal checks

AgentThread beacons to xtrafftrck[.]net:3000/ws/agent

Operator manages victims via Chopi Monitoring Dashboard
```

## Conclusion
During our threat intelligence campaign, we used various web tools to bring together disparate artifacts. Togther hey map out the attackers infrastructure, attack patterns and Opsec strengths and weaknesses. Small mistakes in operator security, like certificate reuse and consistent infrastructure patterns, are what ultimately expose a threat actor's full campaign.

## References

- [Threat Fox](https://threatfox.abuse.ch/browse/tag/chopi/)
- [VirusTotal](https://virustotal.com)
- [Censys](https://search.censys.com)
- [Shodan.io](https://shodan.io)

---

Analysis performed: 2026-05-21 | Analyst: John Ryan