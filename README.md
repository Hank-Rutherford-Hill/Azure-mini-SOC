# Building a SOC + Honeynet in Azure (Live Traffic)
![Cloud Honeynet / SOC](https://i.imgur.com/ZWxe03e.jpg)

## Introduction

For this project, I utilized Microsoft Azure to create a honeynet in order to simulate a weakened environment that allured attackers to attempt to breach the network.  This project allowed me to demonstrate practical knowledge of incident response, system hardening, and overall proficiency on the Azure platform.

## Objective

In this Azure miniature SOC project, the intent of creating a honeynet was to give me the opportunity to evaluate live cyberattacks, evaluate the logs associated with said cyberattacks, investigate alerts, understand attacker's TTPs, and perform incident responste.  I ran an insecure environment for 24 hours, and captured the metrics using Log Analytics Worskapces and created attack maps within sentinel.  Additionally, I focused on hardening the vulnerable environment by re-configuring NSGs, establishing private links & endpoints, and administering regulatory compliance, NIST 800-53, and Microsoft Defender for Cloud recommendations.  Post hardeining, I captured the same metrics for another 24 hour period on a secured system.

The metrics measured are as follows:

- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)

## Azure Components, Technologies, and Frameworks Applied:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace / Kusto Query Language
- Azure Key Vault
- Azure Storage Account
- SIEM (Microsoft Sentinel) 
- Microsoft Defender for Cloud
- Powershell / Powershell ISE / CLI / RDP
- NIST SP 700-53 (Security Controls)
- NIST SP 800-61 (Incident Handling)

## Execution - Phase I - Creating the Honeynet

After opening a free Azure subscription, I created two resource groups.  One resource group housed two VMs (1 Microsoft, 1 Linux) that would constitute the two endpoints of my honeynet.  The other resource group housed a Microsoft "Attacker" VM, which I used to simulate certain attacks, letting me know that my logs were being generated as planned.  Regarding the honeynet VMs, I purposefully misconfigured the firewall and Network Security Group to allow traffic from all ports.  Furthermore, I disabled every setting in Microsoft defender, resulting in a wide open, public internet facing environment that enticed many, many attackers!

## Execution - Phase II - Attack Simulation, Logging and Monitoring

Various attacks were executed with the aforementioned "Attacker" VM.  Powershell was utilized to simulate brute force attempts, malware (EICAR) files, Active Directory brute force success, privilege escalation, and Windows brute force success.  Many organic attacks were also perpetrated on the honeynet.  I used KQL in Log Analytics Workspaces to query data from the logs in order to analyze both the simulated and organic attacks.

## Execution - Phase III - Incident Response

After establishing alert rules, I observed incidents being generated in Sentinel.  I examined several incidents, and for each, I assessed information about the entities involved in these attacks.  I reviewed the IP address, the TTPs / type of attack, and th timeline of each attack.  I made sure to expound upon my investigation by inspecting any related alerts that a particular entity was involved in, in order to further determine the scope of the incident(s) and wether or not an incident could have been a false positive. 

## Execution - Phase IV - Attack Remediation, Implemeting Regulatory Compliance Measures

Post incident response, measures were taken to secure the environment.  I enabled security controls from both NIST 800-53, and Microsoft Defender for Cloud Recoommendations (which, honestly were quite similar to NIST 800-53).  Some of these controls include:

  - Disabling public acccess to the VMs and blob storage account
  - Creating private endpoints for the storage account and VMs
  - Creating an additional NSG for the subnet
  - Enabling private links for key vault
  - Employing a NSG rule to only allow traffic from my IP address

After all of this, I reallocated my honeynet VMs to capture the metrics of a secured environment.

## Execution - Phase V - Results & Metrics Comparison

KQL was used to query logs in order to compare both vulnerable honeynet metrics, and secure environment metrics.  Results were recorded onto a spreadsheet for comparison to determine the effectiveness of the security controls that were employed. 

## Architecture Before Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/aBDwnKb.jpg)

## Architecture After Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/YQNa9Pp.jpg)


For the "BEFORE" metrics, all resources were originally deployed, exposed to the internet. The Virtual Machines had both their Network Security Groups and built-in firewalls wide open, and all other resources are deployed with public endpoints visible to the Internet; aka, no use for Private Endpoints.

For the "AFTER" metrics, Network Security Groups were hardened by blocking ALL traffic with the exception of my admin workstation, and all other resources were protected by their built-in firewalls as well as Private Endpoint

## Attack Maps Before Hardening / Security Controls
![NSG Allowed Inbound Malicious Flows](https://i.imgur.com/1qvswSX.png)<br>
![Linux Syslog Auth Failures](https://i.imgur.com/G1YgZt6.png)<br>
![Windows RDP/SMB Auth Failures](https://i.imgur.com/ESr9Dlv.png)<br>

## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:

  - Start Time 2023-08-12T02:50:07
  - Stop Time 2023-08-13T02:50:07

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 106,441
| Syslog                   | 3,850
| SecurityAlert            | 6
| SecurityIncident         | 594
| AzureNetworkAnalytics_CL | 2,162

## Attack Maps Before Hardening / Security Controls

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:

  - Start Time 2023-08-25T04:54:23
  - Stop Time	2023-08-26T04:54:23

| Metric                   | Count | % Decrease
| ------------------------ | ----- | ----------
| SecurityEvent            | 1,997 | 98.12
| Syslog                   | 25    | 99.35
| SecurityAlert            | 0     | 100
| SecurityIncident         | 0     | 100
| AzureNetworkAnalytics_CL | 0     | 100

## Recap & Reflection

In my Miniature SOC / Azure Honeynet project:

  - A honeynet was created in Azure
  - An "Attacker" VM was utilized to simulate attacks
  - Organic attacks were perpetrated by real cybercriminals
  - Log Analytics Workspaces / KQL were utilized to review logs
  - Attack metrics were captured for a 24 hour window of the honeynet
  - Incidents triggered alerts in Sentinel, which were investigated
  - The honeynet was hardened to become a secure environment
  - Attack metrics were captured for a 24 hour window of the secure environment
  - Results were compared

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.
