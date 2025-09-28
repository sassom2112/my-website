---
title: "Unmasking a Dual-Stage Credential Harvester Operating via RMM Tools"
description: "A detailed incident response writeup on discovering and neutralizing a sophisticated, multi-stage credential harvesting operation leveraging legitimate RMM tools."
tags: ["Incident Response", "Credential Harvesting", "RMM", "LSA", "MITRE ATT&CK", "Exploit", "Assembly", "Blue Team"]
author: "Mike Sasso"
date: "2024-03-22"
heroImage: "/images/credential_harvester_hero.webp"
---

# Unmasking a Dual-Stage Credential Harvester Operating via RMM Tools

<p align="center">
    *** DISCLAIMER ***
</p>

> I'm not a professional; this is strictly educational and may be incorrect


## A Curious Anomaly

My process began with a curious, repetitive anomaly that I found on a Security logs,  **Windows Event ID 4610** - An Authentication packege has been loaded by the Local Security Authority. This event was a level `informational` not even an alert, I almost ingoned it. There was something off about the alert, it had a ScreenConnect DLL being loaded into a privledged area and none of our tools used ScreenConnect. The DLL being loaded was **ScreenConnect.WindowsAuthenticationPackage.dll**, and I had no idea why.

<img 
    src="/screenconnectdll.png" 
    alt="Detailed view of ScreenConnect DLL analysis, highlighting key functionalities." 
    style="max-width: 70%; height: auto; display: block; margin: 2em auto; border-radius: 8px; border: 1px solid #444;" 
/>

> **INSIGHT:** While ScreenConnect is a legit RMM tool, and the use of a custom LSA Authentication Package (ScreenConnect.WindowsAuthenticationPackage.dll) is normal for the application, its presence on a client system that does not authorize or utilize ScreenConnect is a critical security anomaly. This discovery was the catalyst for my hypothesis: I am investigating an instance of unauthorized, high-privileged that leverages legitimate Remote Access Tool component. My next step is to validate this claim by investigating the source and context of the ScreenConnect installation.

## Initial Access and Deployment Methods

Ok, so I started in the middle, where was the initial compromise. We will say for berevity that the initial compromise was a `social engineering` tactic paired and a `trojanized installer`.

### The Initial Access Vector (TA0001)

Once we found the installer file a clearer pictures ensued, this trogan was cleverly disguised as a legitimate application: `Adobe_Reader_V400A18420.msi` that housed out first RMM, Syncro.

<img 
    src="/syncro.png" 
    alt="Detailed view of ScreenConnect DLL analysis, highlighting key functionalities." 
    style="max-width: 100%; height: auto; display: block; margin: 2em auto; border-radius: 8px; border: 1px solid #444;" 
/>

The [Joe Sandbox analysis](https://www.joesandbox.com/analysis/1783678/0/html) confirmed this. The infection chain was initiated by `msiexec.exe` executing this installer, which immediately launched a chain of processes culminating in the deployment of the RMM agents. The initial access vector was a phishing derived, trojanized and awaiting execution by a local administrator to escalate its privileges.

### Living Off the Land (LOTL) Deployment

Upon execution, the attacker didn't rely on a single, custom piece of malware. Instead, they leveraged the trusted nature of commercial Managed Service Provider (MSP) tools, a technique known as "Living Off the Land" (LOTL), deploying a redundant set of legitimate RMM tools:

*   Syncro
*   Atera
*   Two ScreenConnect instances

This approach provides resilient, persistent, and trusted remote access, allowing the attacker to disguise malicious Command and Control (C2) traffic as normal activity.

## Persistence and Evasion Mechanisms (T1543.003, T1497)

The sandbox analysis provided technical details on how the attacker ensures persistence and evades detection using the Syncro installer.

| Technical Mechanism             | MITRE ATT&CK                                 | Joe Sandbox Analysis Details                                                                                                                                                                                                                                                                                              |
| :------------------------------ | :------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Service Persistence             | T1543.003 (Windows Service)                  | The installation used `InstallUtil.exe` to create a dedicated "Syncro" service with a configured automatic restart on failure (after 5, 10, and 60 seconds), ensuring recovery.                                                                                                                                               |
| System Profiling / Evasion      | T1497 (Virtualization/Sandbox Evasion)       | The Syncro service runner performed extensive WMI queries against hardware components (`Win32_PnPEntity`, `Win32_VideoController`, `Win32_PhysicalMemory`, etc.). This systematic environment profiling is characteristic of malware attempting to detect and avoid analysis within a virtual machine or sandbox. |
| C2 Infrastructure & Discovery   | T1105 (Remote Services), T1018 (Remote System Discovery) | Configuration data embedded in the execution reveals endpoints for authentication and C2, including `admin.syncroapi.com` and `realtime.kabutoservices.com`.                                                                                                                                                                  |

## The LSA Persistence Mechanism

The `ScreenConnect.WindowsAuthenticationPackage.dll` that I initially flagged in the Event Viewer was still on my mind. Analyzing the file types brought up another anomonly, while the bulk of the client was written in managed .NET code, the `authentication` and `credential` files were marked as "unmanaged assembly, limited support." This meant they were the low-level binaries, necessary to communicate with the Windows security APIs.

<img 
    src="/screenconnect_code.png" 
    alt="Detailed view of ScreenConnect DLL analysis, highlighting key functionalities." 
    style="max-width: 100%; height: auto; display: block; margin: 2em auto; border-radius: 8px; border: 1px solid #444;" 
/>


So I loaded the unmanaged DLLs into **Ghidra**, to analyze their imported functions. What happens next is pure speculation and I dont have enough background to accurately deduce this far so HIRE ME! DEVELOP ME! I LOVE THIS STUFF!
> This message was brought to you by Mike, he is not beneath begging lulz.

<img 
    src="/assembly.png" 
    alt="Detailed view of ScreenConnect DLL analysis, highlighting key functionalities." 
    style="max-width: 100%; height: auto; display: block; margin: 2em auto; border-radius: 8px; border: 1px solid #444;" 
/>

## Stage 1: Credential Harvesting and Identity Manipulation (T1003.003)

The `ScreenConnect.WindowsAuthenticationPackage.dll` contained direct calls to the following critical, high-privilege APIs:

| API Function (Module)              | Technical Purpose                                                                     | Forensic Conclusion                                                                                                |
| :--------------------------------- | :------------------------------------------------------------------------------------ | :----------------------------------------------------------------------------------------------------------------- |
| `LsaGetLogonSessionData` (SECUR32.DLL) | Retrieves security tokens and credential information from the LSA's memory space.     | Evidence of credential harvesting capability. This is the core function leveraged by tools like Mimikatz. |
| `AllocateLocallyUniqueId` (ADVAPI32.DLL) | Creates a unique ID for a process or user.                                            | Identity & Token Manipulation. Necessary for an attacker to establish a new, possibly temporary, security context. |
| `CreateWellKnownSid` (ADVAPI32.DLL)    | Creates a Security Identifier (SID) for a predefined system group (e.g., Administrators). | Privilege Enumeration/Escalation. Used to check for or construct privileged identity tokens.                          |

I formed a working hypothesis that the attacker was leveraging the ScreenConnect LSA component to achieve high-privilege persistence or "LSA Authentication Package Abuse". While I couldn't prove code injection directly from the assembly code, I gathered strong indirect evidence of the unauthorized installation and configuration change by querying Microsoft Defender Advanced Hunting (KQL).

## Lateral Movement Reconnaissance

## Stage 2: Data Exfiltration and Lateral Movement Reconnaissance (T1537)

Using Microsoft Purview I began a deep KQL investigation. The log completes the picture entire, and I start to get a glimpse of what the attackers action on objective is. I table this moment for the business impact analysis part of the report. 

The log shows 3 different IPs of three cloud providers all querying using APIs designed to interact with Microsoft Outlook's components and the Messaging Application Programming Interface (MAPI). These scripts were fetching a verying request between 9-13 in a single log (jitter?). I piece together a timeline showing the attacker logging in successfully and scraping the victim's Outlook contacts, inbox and drafts among other folders.

This action appears to be entirely unrelated to the preceding activity, which raises a critical question regarding the initial compromise: How did the attacker obtain the victim's password? The possibilities must be investigated:

- Was the password exposed via keylogging?

- Did the identified assembly code inject malicious instructions to capture credentials?

I now believe I have clear evidence of data exfiltration (MITRE ATT&CK: T1537 - Outlook Manipulation). My updated theory is that by successfully extracting the internal contact list, the attacker was preparing a highly effective spear-phishing campaign. This campaign's objective would be to spread the infection laterally to the victim's clients or partners, effectively executing a supply chain compromise.

This dual functionality—stealing credentials at the system level and harvesting contacts at the application level proved this was not a simple RMM deployment, but a meticulously crafted, multi-stage credential harvester.

## Putting the Attacker to Rest

The incident highlights the danger of supply-chain attacks, we think of this attacks through a lens of SolarWinds and MOVEit but they can be legitimate tools like RMM's or signed drivers. 
The response focused on eradicating the threat and neutralizing the techniques used.

| Category                | Remediation Steps Taken                                                                                                                                                                                                  |
| :---------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Eradication             | 1. Full uninstallation of all non-essential RMM tools (Syncro, Atera, ScreenConnect). <br> 2. Deployment of forensic images to confirm no secondary backdoors or custom malware were installed via the RMM channels. |
| System Hardening (Persistence) | Enabled and enforced Local Security Authority (LSA) Protection (RunAsPPL) on all high-value endpoints via Group Policy. This prevents non-Microsoft-signed DLLs from loading into the LSA process, neutralizing the observed persistence vector. |
| Detection Enhancements  | Created new custom detection rules in the Security Information and Event Management (SIEM) system to: <br> 1. Alert on Event ID 4610 where the DLL path is not a standard Microsoft file. <br> 2. Alert on RMM agent processes that execute APIs associated with MAPI/Outlook data access. |
| Identity Reset          | Forced a password reset for all user accounts that authenticated to the compromised machine while the malicious DLL was loaded.                                                                                              |

This investigation successfully moved beyond just isolating a suspicious file. By following the digital breadcrumbs from the Event Viewer and translating the intent through disassembler analysis, we identified a sophisticated, multi-stage attack that weaponized trusted administrative tools for apex credential harvesting.

## References

*   [Joe Sandbox Analysis](https://www.joesandbox.com/analysis/1783678/0/html)
*   [LsaGetLogonSessionData (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsagetlogonsessiondata)
*   [SECURITY_LOGON_SESSION_DATA (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-security_logon_session_data)
*   [A Process Is No One (SpecterOps)](https://specterops.io/wp-content/uploads/sites/3/2022/06/A_Process_is_No_One.pdf)