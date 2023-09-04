# Building a SOC + Honeynet in Azure (Live Traffic)

![image](https://github.com/Hank-Rutherford-Hill/Azure-mini-SOC/assets/143474898/61742e50-bb8d-45f0-8065-2624775e294d)

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
- Virtual Machines (2 Windows, 1 Linux)
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

![image](https://github.com/Hank-Rutherford-Hill/Azure-mini-SOC/assets/143474898/a00e349d-b7a5-4b07-9b03-9aac22afab44)
*As you can see, the Windows-VM-nsg is improperly configured to allow all inbound traffic from anywhere.  The priority (290) is the lowest value of all of my Windows-VM-nsg rules so that it will be adhered to before any other rule.* 

## Execution - Phase II - Attack Simulation, Logging and Monitoring

Various attacks were executed with the aforementioned "Attacker" VM.  Powershell was utilized to simulate brute force attempts, malware (EICAR) files, Active Directory brute force success, privilege escalation, and Windows brute force success.  Many organic attacks were also perpetrated on the honeynet.  I used KQL in Log Analytics Workspaces to query data from the logs in order to analyze both the simulated and organic attacks.

![image](https://github.com/Hank-Rutherford-Hill/Azure-mini-SOC/assets/143474898/b1e5605d-0f78-488f-8f98-08f06b6e3a45)
*Above, you'll see a KQL query that I used to pull some logs from organic attacks against the weakened Windows-VM.  Event ID 4625 signifies 'an account failed to log in'.  In the time range selector section, I selected a custom time range between 8/10/23 and 8/11/23. 
As you can see, there are over 2,500 failed log in attempts in this time frame. These attacks were made possible due to an improperly configured NSG (as seen in the screenshot in 'Execution - Phase I'), and a disabled firewall.*



![image](https://github.com/Hank-Rutherford-Hill/Azure-mini-SOC/assets/143474898/ded5fecf-3545-4f6a-9916-c75a3c4c82dc)


## Execution - Phase III - Incident Response

After establishing alert rules, I observed incidents being generated in Sentinel.  I examined several incidents, and for each, I assessed information about the entities involved in these attacks.  I reviewed the IP address, the TTPs / type of attack, and th timeline of each attack.  I made sure to expound upon my investigation by inspecting any related alerts that a particular entity was involved in, in order to further determine the scope of the incident(s) and wether or not an incident could have been a false positive. 

![image](https://github.com/Hank-Rutherford-Hill/Azure-mini-SOC/assets/143474898/42cb7e12-2b8b-4018-9d13-25170b6f888c)
*For this Azure AD Brute Force Success alert, I assigned myself as an owner, marked the status as 'active', and severity was preset in alert rules to 'High'.*

![image](https://github.com/Hank-Rutherford-Hill/Azure-mini-SOC/assets/143474898/097931a1-b7dc-4ff5-aa2c-12845bdb1739)
*I generated this Brute Force Success attack from my Attack-VM with a Powershell script, so the typical incident response measures were not carried through.  Normally, you would deallocate the machine that was compromised, change the credentials, enable MFA, blcok the IP address (and many more steps).  However, this was just a simulation (and I needed to continue using my Attack-VM to simulate and respond to additional attacks), so when I created the documentation for this event, I *pretended* that I responded with the aforementioned measures!*

## Execution - Phase IV - Attack Remediation, Implemeting Regulatory Compliance Measures

Post incident response, measures were taken to secure the environment.  I enabled security controls from both NIST 800-53, and Microsoft Defender for Cloud Recoommendations (which, honestly were quite similar to NIST 800-53).  Some of these controls include:

  - Disabling public acccess to the VMs and blob storage account
  - Creating private endpoints for the storage account and VMs
  - Creating an additional NSG for the subnet
  - Enabling private links for key vault
  - Employing a NSG rule to only allow traffic from my IP address

After all of this, I was ready to capture the metrics of a secured environment.

## Execution - Phase V - Results & Metrics Comparison

KQL was used to query logs in order to compare both vulnerable honeynet metrics, and secure environment metrics.  Results were recorded onto a spreadsheet for comparison to determine the effectiveness of the security controls that were employed. 

## Architecture / Attack Maps Before Hardening
![image](https://github.com/Hank-Rutherford-Hill/Azure-mini-SOC/assets/143474898/780d6b07-4ef5-43df-8424-92304e5d4a76)


In the "BEFORE" phase of the project, we set up a virtual environment and made it publicly accessible, hoping malicious entities would find it. This phase aimed to draw in these malicious players to study their modes of attack. For this purpose, we established a Windows virtual machine with an SQL database and a Linux server, both with their NSGs set to "Allow All." To make the setup even more tempting, we also launched a storage account and a key vault with public endpoints that were easily accessible on the internet. Throughout this phase, Microsoft Sentinel oversaw the unprotected setup, collecting data through logs compiled in the Log Analytics workspace.

![image](https://github.com/Hank-Rutherford-Hill/Azure-mini-SOC/assets/143474898/9dc31c2d-c1ca-4985-a217-0af0c4223c49)
*This attack map shows SSH authorization failures against my Linux VM.*

  
![image](https://github.com/Hank-Rutherford-Hill/Azure-mini-SOC/assets/143474898/4b02e0bb-a0f5-456c-a213-5e5a5175a96d)
*This attack map shows RDP authorization failures against my Windows VM.*
  
  
![image](https://github.com/Hank-Rutherford-Hill/Azure-mini-SOC/assets/143474898/27d78ff8-6eb2-4a8c-abf5-c62c9ad1430e)
*This attack map shows Microsoft SQL Server (housed on my Windows VM) authorization failures.*

    
![image](https://github.com/Hank-Rutherford-Hill/Azure-mini-SOC/assets/143474898/7e92df8e-2d5f-4817-8b11-556a867405cb)
*This attack map shows the malicious traffic that was allowed through my NSG due to misconfiguration.*
    

## Architecture After Hardening
![image](https://github.com/Hank-Rutherford-Hill/Azure-mini-SOC/assets/143474898/4527e30a-ec51-4349-bd55-0e6b71e30246)


In the project's "AFTER" phase, the environment underwent hardening and security enhancements to meet the standards of NIST SP 800-53 Rev5 SC-7. Below are some of the measures employed:
1. NSGs: We reinforced the NSGs by denying all inbound and outbound traffic, only allowing exceptions for specified public IP addresses needing virtual machine access. This measure guaranteed that only trusted, approved traffic accessed the virtual machines.
2. Built-in Firewalls: We tailored Azure's innate firewalls on the virtual machines to fend off unauthorized access and shield the resources from potentially harmful connections. This adaptation narrowed down the rules for each virtual machine based on its service and roles, reducing the opportunities for malicious actors.
3. Private Endpoints: For a more robust security layer for the Azure Key Vault and Storage Containers, we switched from Public Endpoints to Private Endpoints. This change made sure that these critical resources were only accessible within the virtual network, preventing exposure to the broader internet. 

```NOTE: All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening, so you will see no attack maps in this section!```

## Metrics Before Hardening

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

## Metrics After Hardening

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

Alltogether, this project has been my most enjoyable, learning-filled experience since I went through my Sec+ certification.  Using KQL and Sentinel during this lab helped me grasp concepts needed to pass my Splunk Core User exam as well.  Learning how to use Azure has certainly opened many possibilities in terms of my tech career path.  I am excited to further hone my skills in Azure with future projects, and even obtaining an Azure certification or two!
