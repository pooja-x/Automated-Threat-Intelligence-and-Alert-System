# Automated-Threat-Intelligence-and-Alert-System


The Automated Threat Intelligence and Alert System continuously monitors logs using Wazuh, for real-time threat detection. When a suspicious indicator like file hash or an IP (e.g. Mimikatz) is found, it’s checked via OSINT tools like VirusTotal. If confirmed malicious, an alert is generated and an incident is created in TheHive. Shuffle automates the workflow from detection to enrichment and response. If Mimikatz is detected, the system treats it as a threat and sends an email to the SOC analyst to confirm IP blocking via a response script, enabling quick yet controlled action. 

