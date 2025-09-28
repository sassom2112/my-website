---
title: "Lessons from a Dual-Stage Attack Operating via RMM Tools"
description: "A detailed incident response on discovering and mitigating a multi-stage operation that leveraged legitimate RMM tools"
tags: ["Incident Response", "Assembly", "Blue Team"]
author: "Mike Sasso"
date: "2024-03-22"
heroImage: "/images/credential_harvester_hero.webp"
---

# Unmasking a Dual-Stage Credential Harvester Operating via RMM Tools

<p align="center">
    *** DISCLAIMER ***
</p>
<p align="center">
    I am not a DFIR professional; this is strictly educational and may be incorrect
</p>




## A Curious Anomaly

My process began with a curious, repetitive anomaly that I found on a security log, **Windows Event ID 4610**, an authentication package has been loaded by the Local Security Authority. This event was a level `informational` not even an alert, I almost ignored it. There was something off about the log, it was a ScreenConnect DLL file being loaded into a privileged area but more importantly, we dont use ScreenConnect. The DLL being loaded was **ScreenConnect.WindowsAuthenticationPackage.dll**, and I had no idea why.

<img 
    src="/screenconnectdll.png" 
    alt="Detailed view of ScreenConnect DLL analysis, highlighting key functionalities." 
    style="max-width: 70%; height: auto; display: block; margin: 2em auto; border-radius: 8px; border: 1px solid #444;" 
/>

> **INSIGHT:** While ScreenConnect is a legit RMM tool, and the use of a custom LSA Authentication Package (ScreenConnect.WindowsAuthenticationPackage.dll) is normal for the application, its presence on a client system that does not authorize or utilize ScreenConnect is a critical security anomaly. This discovery was the catalyst for my hypothesis: I am investigating an instance of a unauthorized, high-privilege process that leveraged a legitimate Remote Access Tool component. My next step would be to validate this claim by investigating the source and context of the ScreenConnect installation.

## Initial Access and Deployment Methods

I started in the middle of the story, which left me missing the context. I had to track back to find the initial point of compromise. To be brief, that compromise was a `social engineering` tactic paired and a `trojanized installer`.

### The Initial Access Vector (TA0001)

Once I found the installer file a clearer picture ensued, this trojan was cleverly disguised as a common application: `Adobe_Reader_V400A18420.msi` which contained our first RMM, Syncro.

<img 
    src="/syncro.png" 
    alt="Detailed view of ScreenConnect DLL analysis, highlighting key functionalities." 
    style="max-width: 100%; height: auto; display: block; margin: 2em auto; border-radius: 8px; border: 1px solid #444;" 
/>

The dynamic analysis from [Joe’s Sandbox](https://www.joesandbox.com/analysis/1783678/0/html) confirmed that that Syncro RMM was hidden inside the Adobe Reader MSI. The infection chain was initiated by `msiexec.exe`, which immediately launched a chain of processes culminating in the deployment of the RMM agents. The initial access vector was phishing derived, trojanized and awaiting execution by a local administrator to escalate its privileges.

### Living Off the Land (LOTL) Deployment

Upon execution, the attacker didn't rely on a single, custom piece of malware. Instead, they leveraged the trusted nature of Managed Service Provider (MSP) tools, a technique known as "Living Off the Land" (LOTL), and even deployed a redundant set of RMM tools:

*   Syncro
*   Splashtop
*   Atera
*   (x2) ScreenConnect


The dynamic analysis provided technical details on how the attacker ensures persistence and evades detection using the Syncro installer.

## Persistence and Evasion Mechanisms (T1543.003, T1497)

The sandbox analysis provided technical details on how the attacker ensures persistence and evades detection using the Syncro installer.

| Technical Mechanism             | MITRE ATT&CK                                 | Joe Sandbox Analysis Details                                                                                                                                                                                                                                                                                              |
| :------------------------------ | :------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Service Persistence             | T1543.003 (Windows Service)                  | The installation used `InstallUtil.exe` to create a dedicated "Syncro" service with a configured automatic restart on failure (after 5, 10, and 60 seconds), ensuring recovery.                                                                                                                                               |
| System Profiling / Evasion      | T1497 (Virtualization/Sandbox Evasion)       | The Syncro service runner performed extensive WMI queries against hardware components (`Win32_PnPEntity`, `Win32_VideoController`, `Win32_PhysicalMemory`, etc.). This systematic environment profiling is characteristic of malware attempting to detect and avoid analysis within a virtual machine or sandbox. |
| C2 Infrastructure & Discovery   | T1105 (Remote Services), T1018 (Remote System Discovery) | Configuration data embedded in the execution reveals endpoints for authentication and C2, including `admin.syncroapi.com` and `realtime.kabutoservices.com`.                                                                                                                                                                  |

## The LSA Persistence Mechanism

Now with the initial attack vector mapped and the `ScreenConnect.WindowsAuthenticationPackage.dll` from the Event Viewer log still on my mind. I began to statically analyze DLL’s for IoC’s. The file types brought up another anomaly, while most of the files were written in .NET code, the `authentication` and `credential` files were `assembly`. This meant they were the low-level binaries, necessary to communicate with the Windows security APIs.

<img 
    src="/screenconnect_code.png" 
    alt="Detailed view of ScreenConnect DLL analysis, highlighting key functionalities." 
    style="max-width: 100%; height: auto; display: block; margin: 2em auto; border-radius: 8px; border: 1px solid #444;" 
/>


So I dug further and loaded the unmanaged DLLs into **Ghidra**, to analyze their imported functions. 

> #### Now, what happens next is pure speculation and I don’t have a DFIR background but I am learning…


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

*   [LsaGetLogonSessionData (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsagetlogonsessiondata)
*   [SECURITY_LOGON_SESSION_DATA (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-security_logon_session_data)

With this newfound information, I formed a working hypothesis that the attacker was leveraging the ScreenConnect LSA component to achieve high-privilege persistence or "LSA Authentication Package Abuse". While I couldn't prove code injection directly from the assembly code, I gathered strong indirect evidence that the attacker had stolen the victim’s credentials and was exfiltrating data. This evidence was found by querying Microsoft `E-Discovery` using `KQL`.

## Lateral Movement Reconnaissance

## Stage 2: Data Exfiltration and Lateral Movement Reconnaissance (T1537)

Using Microsoft Purview’s E-Dicovery I began a deep KQL investigation. The log gives us evidence to the attacker’s `Action on Objective`. Highlighting the real-world `business impact`. 


The log shows 3 different IPs from three cloud providers all querying outlook using APIs designed to interact with Microsoft Outlook's components and the Messaging Application Programming Interface (MAPI). These scripts used varying `GET` request, between 9-13 in a single call, maybe to introduce jitter. I pieced together a timeline that showed the attacker logging in successfully and scraping the victim's Outlook contacts, inbox and drafts among other folders.

These actions appear to be entirely unrelated to the preceding activity, which raises a critical question regarding the initial compromise: How did the attacker obtain the victim's password? The possibilities must be investigated:

- Was the password exposed via keylogging?

- Did the identified assembly code inject malicious instructions to capture credentials?

I now believe I have clear evidence of data exfiltration (MITRE ATT&CK: T1537 - Outlook Manipulation). My updated theory is that by successfully extracting the internal contact list, the attacker was preparing a highly effective spear-phishing campaign. 


This dual functionality—stealing credentials at the system level and harvesting contacts at the application level proved this was not a simple RMM deployment, but a meticulously crafted, multi-stage attack.

## The Outcome

The incident highlights the evolution of the supply chain attack, which extends far beyond the zero-day or unpatched vulnerability model. While the supply chain attack target the software's build pipeline, modern attacks increasingly leverage legitimate, trusted tools like RMM applications. They achieve this by weaponizing the tool's intended function or abusing its dependencies through advanced techniques such as: LSA Authentication Package Abuse, DLL search order hijacking, or code injection into a legitimate, signed binary. 

> #### I defined the multi-stage attack and attack vector through root-cause analysis, tracing its origin to a `local admin policy` violation.
> #### I translated complex technical findings (Trojan, Dropper, data scraping) into clear `business impact`, demonstrating what was lost in a short time to secure future `stakeholder buy-in`. 
> #### I Led the creation and delivery of a `lessons learned` tabletop exercise to directly address the `policy gap` (standard user only), permanently strengthening the client's `security posture` against similar future threats.

## References

*   [Joe Sandbox Analysis](https://www.joesandbox.com/analysis/1783678/0/html)
*   [LsaGetLogonSessionData (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsagetlogonsessiondata)
*   [SECURITY_LOGON_SESSION_DATA (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-security_logon_session_data)
*   [A Process Is No One (SpecterOps)](https://specterops.io/wp-content/uploads/sites/3/2022/06/A_Process_is_No_One.pdf)