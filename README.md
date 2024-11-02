# The Data Dig: Investigating the "Excel Macro Pushes Lokibot" Incident

An in-depth cybersecurity analysis project focused on dissecting and mitigating a malware incident involving a malicious Excel macro delivering the Lokibot credential stealer. This project is part of the **CYB102 Capstone** and was conducted in collaboration with Group 17.

## 📋 Project Overview
In this project, our team, consisting of cyber “Techno-Archeologists,” analyzed a dataset derived from a malicious Excel spreadsheet macro pushing Lokibot, a credential-stealing malware. Our objective was to understand the methods and impact of this malware attack, using industry-standard incident response frameworks and tools.

- **Dataset**: ["Excel Macro Pushes Lokibot"](https://www.malware-traffic-analysis.net/2020/10/12/index.html) from Malware-traffic-analysis.net
- **Playbook**: NIST Computer Security Incident Handling Guide (SP 800-61, Revision 2)
- **Tools**: Wireshark, NetworkMiner, VirusTotal, Catalyst

## 🧑‍💻 Team Members
- **Areeb Ehsan**
- **Emran Habib**
- **Dheeraj Kumar** 
- **Niles Buchanan**
- **Wenhao Xue** 


## 🎯 Objectives
- To identify the tactics, techniques, and procedures (TTPs) used in the attack.
- To analyze the malware's impact on the system, including registry modifications and persistent credential theft.
- To provide detailed recommendations and mitigations for preventing similar incidents.

## 🔍 Dataset Information
The dataset for this project originates from a malicious spam email containing an Excel macro. When executed, this macro downloads Lokibot, an information-stealing malware, which then modifies the Windows registry to establish persistence.

- **Threat Expected Findings**:
  - Credential theft by Lokibot from infected machines.
  - Downloading files covertly via the macro in Excel.
  - Obfuscation to disguise malware as a benign program.

## 📖 Playbook: NIST Incident Response Guide
We followed the NIST Computer Security Incident Handling Guide to conduct a structured analysis of the malware incident. This comprehensive playbook was chosen for its standardized approach to incident response and alignment with compliance requirements.

## 🛠️ Tools Used
1. **Wireshark**: For HTTP traffic analysis and identifying unusual network patterns.
2. **NetworkMiner**: To examine downloaded files and suspicious connections.
3. **VirusTotal**: To verify malicious files and hash values.
4. **Catalyst**: For aggregating logs and understanding exfiltration patterns.

## 📈 Analysis Summary

### Monitoring Sources
- **Email Logs**: Monitored for phishing attempts and malicious macro-laden emails.
- **Network Logs**: Inspected for unusual traffic patterns, specifically connections to Lokibot’s command and control servers.

### Impact Analysis
- **Incident Impact**: The malware modifies registry keys and establishes persistence, posing a high-severity threat.
- **Affected Systems**: Primarily targets Microsoft Office applications, with attempts to restrict CD/DVD drive access.

### Incident Response
Following the playbook, we:
1. Detected unusual HTTP traffic linked to the malicious Excel file.
2. Isolated the infected system and quarantined the malicious file.
3. Identified specific IOCs, including malicious IPs and file hashes.

### Tactics, Techniques, and Procedures (TTPs)
1. **Phishing for Malware Delivery**: Using Excel macros in emails to spread Lokibot.
2. **File-Based IOCs**: Detected a malicious file with SHA256 hash `d5a68a111c...`.
3. **Network Traffic to Malicious IPs**: HTTP traffic observed to IP `45[.]14[.]112[.]133`.

### Indicators of Compromise (IOCs)
- **File Hash**: `d5a68a111c359a22965206e7ac7d602d92789dd1aa3f0e0c8d89412fc84e24a5`
- **Malicious IP Address**: `45.14.112.133`

## 🛡️ Remediation Steps
To mitigate similar incidents, we recommend:
1. **Technical Measures**:
   - **Disabling Macros** in MS Office by default.
   - **Upgrading Endpoint Security** systems.
   - **Enhanced Email Filtering** to block suspicious attachments.
   - **Implementing Access Controls** to limit macro-enabled documents.
2. **User Education**:
   - Security awareness training to recognize phishing emails.
3. **System Hardening**:
   - Applying patches, updating firewall rules, and continuous monitoring.

