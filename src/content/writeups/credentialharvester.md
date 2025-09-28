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
    **DISCLAIMER**
</p>

> Please note that I am **not a professional DFIR analyst or Incident Responder**. This writeup is strictly part of a personal educational journey and, as such, may contain significant errors. This site is a personal project (built with JS, Astro, CSS, and HTML) and is not part of any professional platform.

## So I had a fun week…

Also, this is why you don’t give clients local administration rights… smh.

## A Curious Anomaly

When responding to an incident, we learn to trust our tools. My process began not with a siren-blaring alert, but with a curious, repetitive anomaly flagged deep within a client's system logs: **Windows Event ID 4610**. This event signaled the successful loading of an Authentication Package by the Local Security Authority (LSA); the security heart of Windows.

Crucially, the DLL being loaded wasn't the expected `msv1_0.DLL`; it was a third-party file: **ScreenConnect.WindowsAuthenticationPackage.dll**. I thought to myself, "We do not have this tool. Why is ScreenConnect even on our clients computer?"

<img 
    src="/screenconnectdll.png" 
    alt="Detailed view of ScreenConnect DLL analysis, highlighting key functionalities." 
    style="max-width: 70%; height: auto; display: block; margin: 2em auto; border-radius: 8px; border: 1px solid #444;" 
/>

> **CRITICAL INSIGHT:** This finding was the **linchpin** of the entire investigation. While **ScreenConnect** is a legitimate Remote Monitoring and Management (**RMM**) tool, it was not one of our tools. So, while a non-Microsoft DLL gaining access to the **LSA** process isn't an alarm by itself, this specific discovery was the **catalyst** for my hypothesis: that something else entirely was at play. 🔥

## Initial Access and Deployment Methods

My first step was to trace the initial compromise. The evidence pointed immediately to a clever social engineering tactic paired with a trojanized installer.

### The Initial Access Vector (TA0001)

File system analysis revealed the malicious execution began with a trojanized Windows Installer file, cleverly disguised as a legitimate application: `Adobe_Reader_V400A18420.msi` that housed the Syncro RMM.

<img 
    src="/syncro.png" 
    alt="Detailed view of ScreenConnect DLL analysis, highlighting key functionalities." 
    style="max-width: 100%; height: auto; display: block; margin: 2em auto; border-radius: 8px; border: 1px solid #444;" 
/>

The [Joe Sandbox analysis](https://www.joesandbox.com/analysis/1783678/0/html) confirmed this: the infection chain was initiated by `msiexec.exe` executing this installer, which immediately launched a chain of processes culminating in the deployment of the RMM agents. This confirms the initial access vector was a phishing-delivered, trojanized MSI.

### Living Off the Land (LOTL) Deployment

Upon execution, the attacker didn't rely on a single, custom piece of malware. Instead, they leveraged the trusted nature of commercial Managed Service Provider (MSP) tools, a technique known as "Living Off the Land" (LOTL), deploying a redundant set of legitimate RMM tools:

*   Syncro
*   Atera
*   Two ScreenConnect instances

This approach provides resilient, persistent, and trusted remote access, allowing the attacker to disguise malicious Command and Control (C2) traffic as normal IT maintenance activity.

## Persistence and Evasion Mechanisms (T1543.003, T1497)

The sandbox analysis provided crucial technical detail on how the attacker ensures persistence and evades detection using the Syncro installer.

| Technical Mechanism             | MITRE ATT&CK                                 | Joe Sandbox Analysis Details                                                                                                                                                                                                                                                                                              |
| :------------------------------ | :------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Service Persistence             | T1543.003 (Windows Service)                  | The installation used `InstallUtil.exe` to create a dedicated "Syncro" service with a configured automatic restart on failure (after 5, 10, and 60 seconds), ensuring recovery.                                                                                                                                               |
| System Profiling / Evasion      | T1497 (Virtualization/Sandbox Evasion)       | The Syncro service runner performed extensive WMI queries against hardware components (`Win32_PnPEntity`, `Win32_VideoController`, `Win32_PhysicalMemory`, etc.). This systematic environment profiling is characteristic of malware attempting to detect and avoid analysis within a virtual machine or sandbox. |
| C2 Infrastructure & Discovery   | T1105 (Remote Services), T1018 (Remote System Discovery) | Configuration data embedded in the execution reveals endpoints for authentication and C2, including `admin.syncroapi.com` and `realtime.kabutoservices.com`.                                                                                                                                                                  |

## The LSA Persistence Mechanism

The `ScreenConnect.WindowsAuthenticationPackage.dll` that I initially flagged in the Event Viewer was the attacker's preferred persistence mechanism. The file path confirmed the DLL belonged to the ScreenConnect client installation. Analyzing the file types confirmed a critical detail: while the bulk of the client was written in managed .NET code, the authentication and credential files were marked as "unmanaged assembly, limited support." This meant they were native binaries, necessary to communicate with the low-level Windows security APIs.

<img 
    src="/screenconnect_code.png" 
    alt="Detailed view of ScreenConnect DLL analysis, highlighting key functionalities." 
    style="max-width: 100%; height: auto; display: block; margin: 2em auto; border-radius: 8px; border: 1px solid #444;" 
/>

### Speaking the Language of Native Code

To understand the DLL's true function, I loaded the unmanaged DLLs into **Ghidra**, a disassembler and decompiler, to analyze their imported functions. This process turned from a suspicious activity to a confirmed malicious event.

<img 
    src="/assembly.png" 
    alt="Detailed view of ScreenConnect DLL analysis, highlighting key functionalities." 
    style="max-width: 100%; height: auto; display: block; margin: 2em auto; border-radius: 8px; border: 1px solid #444;" 
/>

## Stage 1: Credential Harvesting and Identity Manipulation (T1003.003)

The disassembled code immediately flagged the attacker's primary objective: credential theft. The `ScreenConnect.WindowsAuthenticationPackage.dll` contained direct calls to the following critical, high-privilege APIs:

| API Function (Module)              | Technical Purpose                                                                     | Forensic Conclusion                                                                                                |
| :--------------------------------- | :------------------------------------------------------------------------------------ | :----------------------------------------------------------------------------------------------------------------- |
| `LsaGetLogonSessionData` (SECUR32.DLL) | Retrieves security tokens and credential information from the LSA's memory space.     | Evidence of credential harvesting capability. This is the core function leveraged by tools like Mimikatz. |
| `AllocateLocallyUniqueId` (ADVAPI32.DLL) | Creates a unique ID for a process or user.                                            | Identity & Token Manipulation. Necessary for an attacker to establish a new, possibly temporary, security context. |
| `CreateWellKnownSid` (ADVAPI32.DLL)    | Creates a Security Identifier (SID) for a predefined system group (e.g., Administrators). | Privilege Enumeration/Escalation. Used to check for or construct privileged identity tokens.                          |

The combined use of these functions suggests that the DLL was designed not merely to log a user on remotely, but to steal the credentials/token from that session and manipulate the user's security context.

## Lateral Movement Reconnaissance

## Stage 2: Data Exfiltration and Lateral Movement Reconnaissance (T1537)

Further analysis of the executable’s imports revealed a shocking second stage: data exfiltration for lateral movement.

The code contained calls to APIs designed to interact with Microsoft Outlook's components and the Messaging Application Programming Interface (MAPI). Specifically, the attacker was targeting systemic APIs that suggest the enumeration and scraping of user data:

*   The focus was on the most valuable internal data for a subsequent campaign: the user's Inbox, Drafts, and Contacts Lists.
*   This action is entirely unrelated to remote administration and is definitive proof of data theft (**MITRE ATT&CK: T1537 - Outlook Manipulation**). By successfully extracting the internal contact list, the attacker was preparing a highly effective spear-phishing campaign to spread the infection laterally to the victim's clients or partners, confirming a major risk of supply chain compromise.

This dual functionality—stealing credentials at the system level and harvesting contacts at the application level—proved this was not a simple RMM deployment, but a meticulously crafted, multi-stage credential harvester.

## Putting the Attacker to Rest

The incident highlights the danger of trusted third-party tools. Our response focused on eradicating the threat and neutralizing the techniques used.

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