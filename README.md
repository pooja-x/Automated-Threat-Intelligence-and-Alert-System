# Automated-Threat-Intelligence-and-Alert-System


# Introduction

   In an era where cyber threats are becoming increasingly sophisticated, organizations require security systems that can detect and respond to attacks instantly. This project presents an Automated Threat Detection and Response System that leverages powerful open-source tools to provide real-time monitoring, verification, and incident management. Wazuh continuously scans system logs to identify suspicious indicators such as malicious IP addresses or file hashes, which are then cross-checked with VirusTotal for threat validation. 
    Once a threat is confirmed, an incident is automatically created in TheHive, enabling structured investigation and tracking. The workflow is fully orchestrated using Shuffle, ensuring seamless integration between detection, enrichment, and response processes. Deployed on AWS for scalability and reliability, the system also incorporates a controlled action mechanism — sending an email to SOC analysts for IP blocking approval, thereby balancing automation speed with human oversight.


# Architecture Diagram



1. Flowchart <img width="847" height="340" alt="FlowChart" src="https://github.com/user-attachments/assets/ef0a9854-4333-460f-9f73-e1a7229eb109" />
                  


   
2. Workflow <img width="847" height="695" alt="Workflow" src="https://github.com/user-attachments/assets/3ed3ad26-e298-4319-8f9a-1852e0e8b9e1" />
                    


3. Details  <img width="867" height="615" alt="Detailed Workflow" src="https://github.com/user-attachments/assets/f1d563e1-994a-48b9-a20f-0206965b7b0a" />
                    



# Tools and Technologies 

- Sysmon:- A Windows system monitoring tool that logs system activity like process creation,
           network connections, and file changes to help detect malicious behavior.
- Mimikatz:- A post-exploitation tool often used by attackers (and defenders in testing) to extract
             passwords, hashes, and Kerberos tickets from Windows systems.
- Wazuh:- An open-source security platform for threat detection, compliance, and incident
 response that collects and analyzes security data from endpoints.
- TheHive:- A scalable open-source Security Incident Response Platform (SIRP) used by SOC
 teams to manage and investigate security incidents collaboratively.
- Shuffle:- An open-source security automation platform that allows users to create workflows
 connecting tools like SIEMs and SOARs.
- VirusTotal:- Online tool for comprehensive threat analysis and malware detection.
- AWS EC2:- Scalable cloud computing service for running virtual servers.



# Implementation

- Servers/VMs:
   - SIEM Server → Wazuh  
   - Threat Intel API → VirusTotal 
   - Incident Management → TheHive 
   - Automation Orchestrator → Shuffle
 
- Mimikatz – Example Detection Scenario
     - Mimikatz, a well-known credential-dumping tool, is used in this project as a test case for detection and response.
     - If Wazuh detects a Mimikatz-related signature, the event is forwarded to TheHive via Shuffle.
     - Shuffle enriches the alert, confirms its malicious nature, and marks it as Critical, prompting SOC analysts to take immediate action. 

 
  <img width="920" height="618" alt="mimikatz executed" src="https://github.com/user-attachments/assets/b3dd7839-9471-4eeb-8996-cbfd5c61962f" />




- Wazuh – Real-time Threat Detection
     - Wazuh is deployed as the primary SIEM solution to continuously monitor logs from endpoints, servers, and network devices. 
     - It uses predefined and custom security rules to detect suspicious activities, anomalies, and potential malware behaviors. 
     - When a suspicious event is detected (e.g., unusual PowerShell execution), Wazuh generates an alert with detailed information, including the source, time, and type of threat.
 
 
  <img width="920" height="461" alt="wazuh_agent_active" src="https://github.com/user-attachments/assets/0708477a-d821-4fb9-955a-991123068a99" />


 - TheHive – Incident Management 
     - Wazuh alerts are automatically sent to TheHive, an open-source incident response platform. 
     - Each alert from Wazuh is converted into a case in TheHive, enabling SOC analysts to track, investigate, and document the incident lifecycle. 
     - TheHive provides a centralized interface for managing multiple incidents and collaborating with other analysts.
  

 - Shuffle – Workflow Automation 
     - Shuffle acts as an automation layer between Wazuh, TheHive, and OSINT tools (like VirusTotal). 
     - When an alert is generated, Shuffle triggers a workflow to enrich the data by checking the file hash or IP against threat intelligence sources. 
     - If the result confirms malicious intent, Shuffle updates the TheHive case with enriched data and flags it for immediate response. 

<img width="955" height="775" alt="shuffle" src="https://github.com/user-attachments/assets/1e08e5d2-b6d4-4266-96f8-01ff40c11554" />




 - Automated Email Notifications 
     - As part of the automated response, Shuffle sends an email notification to SOC analysts whenever a confirmed malicious event (e.g., Mimikatz detection) occurs. 
     - The email contains all relevant incident details, including source IP, timestamp, threat description, and a direct link to the TheHive case. 
     - This ensures rapid awareness and allows analysts to initiate containment actions promptly.


 <img width="952" height="539" alt="email-notification" src="https://github.com/user-attachments/assets/4d7f5dab-dfce-416b-a6b4-028e0f1bdab2" />



 - Wazuh – Mimikatz Detected Logs
     
     - CLI:- In /var/ossec/logs/archives/archives.json file 
  <img width="952" height="497" alt="mimikatz_logs_CLI" src="https://github.com/user-attachments/assets/8678ae7d-f448-4115-bfdc-75972968a7b0" />



     - Wazuh Dashboard 
   <img width="952" height="494" alt="wazuh_dashboard" src="https://github.com/user-attachments/assets/8dcbeba2-6ea7-410d-bb7d-d8a1f3265cf4" />



     - Detailed Log
   <img width="952" height="499" alt="detailed" src="https://github.com/user-attachments/assets/e0e8032f-d48d-4635-ba45-49d342778c5d" />










