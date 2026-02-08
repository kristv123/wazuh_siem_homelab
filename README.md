# Wazuh SIEM Homelab – Threat Detection with VirusTotal Integration

## Overview
This project documents a home SIEM lab built using Wazuh to simulate real-world threat detection and alerting workflows in a multi-host Ubuntu environment.

The lab focuses on file-based threat detection, alert enrichment, and validating SIEM workflows commonly used in SOC environments. The lab is based on [video](https://www.youtube.com/watch?v=YWCpXdqj1wU) by Joshua Clarke as well as the official Wazuh [documentation](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html). 

## Lab Architecture
- 1x Wazuh Manager
- 1x Ubuntu Linux endpoint (agent)
- 1x Windows endpoint (agent, will be added in future)
- File Integrity Monitoring (FIM) enabled
- Custom detection rules
- VirusTotal API integration for malware scanning
- Active response enabled for malicious file removal

## Objectives
- Simulate enterprise-style SIEM monitoring
- Detect unauthorized or suspicious file activity
- Enrich alerts using external threat intelligence
- Validate detection logic through controlled testing

## Detection Workflow
1. A file is added to a monitored directory on an Ubuntu endpoint
2. Wazuh File Integrity Monitoring (FIM) detects the change
3. A script (based on the Wazuh virustotal proof of concept guide) triggers a VirusTotal API scan
4. Scan results are parsed and correlated
5. An alert is generated in the Wazuh dashboard if malicious indicators are found
6. The malicious file is removed using active response script configured in `ossec.conf`

## Technologies Used
- Wazuh (SIEM / XDR)
- Ubuntu Server
- Ubuntu Agent
- VirusTotal API
- Bash
- Linux auditing & logging

## Simulated Threat Scenarios
- Introduction of known-malicious files into monitored directories (`/tmp/malware directory`)
- Validation of detection accuracy and alert severity
- Review of enriched alerts within the Wazuh dashboard

## Security Considerations
- No API keys, credentials, or production logs are stored in this repository
- All testing performed in an isolated lab environment using virtual machines in VMware Workstation

## Key Takeaways
- Hands-on experience configuring SIEM detections
- Practical understanding of FIM-based threat detection
- Experience integrating external threat intelligence into SIEM workflows
- Improved alert fidelity through enrichment and correlation

## Simulating attack using Eicar test file
To validate the detection pipeline, the EICAR test file was placed into a monitored directory (`/tmp/malware`) on the Ubuntu endpoint using curl.

This action triggered:
- File Integrity Monitoring alert
- VirusTotal hash lookup
- Enriched alert generation within the Wazuh dashboard
- Removal of the file

This confirms correct end-to-end detection and alert enrichment functionality.

## Future Improvements and Uses of Home-lab
- More advanced attack simulations
- Additional endpoint telemetry (process, network activity)
- Additional endpoints



