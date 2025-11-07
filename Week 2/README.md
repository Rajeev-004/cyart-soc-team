1. Alert Management Practice
Activities:
Tools: Google Sheets, Wazuh, TheHive.
Tasks: Create an alert classification system, prioritize alerts, document response procedures, create incident tickets, and practice escalation.
Enhanced Tasks:
Alert Classification System: Create a Google Sheets table to map alerts to MITRE ATT&CK techniques:
| Alert ID | Type        | Priority | MITRE Tactic       |
|----------|-------------|----------|--------------------|
| 001      | Phishing    | High     | T1566             |
Test with a mock alert (e.g., “Phishing Email: Suspicious Link”).
Prioritize Alerts: Simulate alerts (e.g., “Critical: Log4Shell Exploit Detected” vs. “Low: Port Scan”) and score using CVSS in Google Sheets. Example: Log4Shell CVSS 9.8 = Critical.
Dashboard Creation: In Wazuh, create a dashboard to visualize alert priorities (e.g., pie chart for Critical vs. High alerts).
Incident Ticket: Draft a ticket in TheHive with fields:
Title: [Critical] Ransomware Detected on Server-X
Description: Indicators: [File: crypto_locker.exe], [IP: 192.168.1.50]
Priority: Critical
Assignee: SOC Analyst
Escalation Role-Play: Draft a 100-word email to escalate a Critical alert to Tier 2, summarizing the incident and IOCs.

2. Response Documentation
Activities:
Tools: Google Docs, Draw.io.
Tasks: Create incident response templates, document investigation steps, create checklists, and conduct a mock post-mortem.
Enhanced Tasks:
Incident Response Template: Use a SANS template in Google Docs to document a mock phishing incident:
1. Executive Summary
2. Timeline
3. Impact Analysis
4. Remediation Steps
5. Lessons Learned
Investigation Steps: Log actions for a mock incident:
| Timestamp            | Action                     |
|----------------------|----------------------------|
| 2025-08-18 14:00:00 | Isolated endpoint          |
| 2025-08-18 14:30:00 | Collected memory dump      |
Phishing Checklist: Create a checklist in Google Docs:
- [ ] Confirm email headers
- [ ] Check link reputation (VirusTotal)
- [ ] Identify affected users
Post-Mortem: Summarize lessons learned from a simulated breach in 50 words, focusing on process improvements.

3. Alert Triage Practice
Activities:
Tools: Wazuh, VirusTotal, AlienVault OTX.
Tasks: Simulate triage with sample alerts and validate false positives.
Enhanced Tasks:
Triage Simulation: Analyze a mock alert (e.g., “Brute-force SSH Attempts”) in Wazuh. Document:
| Alert ID | Description            | Source IP      | Priority | Status |
|----------|------------------------|----------------|----------|--------|
| 002      | Brute-force SSH        | 192.168.1.100  | Medium   | Open   |
Threat Intelligence Validation: Cross-reference the alert’s IP or file hash with AlienVault OTX to validate IOCs. Summarize findings in 50 words.

4. Evidence Preservation
Activities:
Tools: Velociraptor, FTK Imager.
Tasks: Practice evidence preservation and chain-of-custody documentation.
Enhanced Tasks:
Volatile Data Collection: Use Velociraptor to collect network connections (SELECT * FROM netstat) from a Windows VM. Save to CSV.
Evidence Collection: Collect a memory dump (SELECT * FROM Artifact.Windows.Memory.Acquisition) and hash it using sha256sum. Document:
| Item       | Description       | Collected By | Date       | Hash Value        |
|------------|-------------------|--------------|------------|-------------------|
| Memory Dump| Server-X Dump     | SOC Analyst  | 2025-08-18 | <SHA256>          |

5. Capstone Project: Full Alert-to-Response Cycle
Activities:
Tools: Metasploit, Wazuh, CrowdSec, Google Docs.
Tasks: Simulate an attack, detect, triage, respond, and document.
Enhanced Tasks:
Attack Simulation: Exploit a Metasploitable2 vulnerability with Metasploit (e.g., vsftpd backdoor: use exploit/unix/ftp/vsftpd_234_backdoor). Follow Metasploit Unleashed.
Detection and Triage: Configure Wazuh to alert on the attack. Document:
| Timestamp            | Source IP      | Alert Description | MITRE Technique |
|----------------------|----------------|-------------------|-----------------|
| 2025-08-18 11:00:00 | 192.168.1.100  | VSFTPD exploit    | T1190          |
Response: Isolate the VM and block the attacker’s IP with CrowdSec. Verify with a ping test.
Reporting: Write a 200-word report in Google Docs using a SANS template, including Executive Summary, Timeline, and Recommendations.
Stakeholder Briefing: Draft a 100-word briefing for a non-technical manager, summarizing the incident and actions taken.