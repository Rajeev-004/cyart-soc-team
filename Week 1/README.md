# Week 1 – SOC Fundamentals, Monitoring & Incident Response

This week introduces the foundational concepts of Security Operations Centers (SOC), including their purpose, workflow, tools, and incident response processes.  
Students will gain hands-on experience in log collection, analysis, alert configuration, and documentation within a mini-SOC lab environment.

---

- Learning Objectives
  - Understand SOC structure, roles, and responsibilities
  - Learn key security monitoring and log management fundamentals
  - Explore core security tools such as SIEM, EDR, IDS/IPS, and vulnerability scanners
  - Apply basic security concepts including the CIA triad, threats, vulnerabilities, and risk
  - Follow standard SOC workflows and incident response lifecycles
  - Practice documenting security events, creating dashboards, and configuring alerts

---

## Theoretical Knowledge

- SOC Fundamentals and Operations Learn:
  - Purpose: Proactive threat detection, incident response, continuous monitoring
  - Roles: Tier 1/2/3 analysts, SOC manager, threat hunters
  - Key Functions: Log analysis, alert triage, threat intelligence integration
  - References: NIST frameworks, MITRE ATT&CK, IBM & Microsoft SOC walkthrough videos

---

- Security Monitoring Basics Learn:
  - Objectives: Detect anomalies, unauthorized access, and policy violations
  - Tools: SIEM (Splunk, Elastic), network traffic analyzers (Wireshark)
  - Key Metrics: False positives/negatives, Mean Time to Detect (MTTD)
  - References: Elastic SIEM guides, Boss of the SOC datasets

---

- Log Management Fundamentals Learn:
  - Log Lifecycle: Collection, normalization, storage, retention, analysis
  - Common Log Types: Windows Event Logs, Syslog, HTTP server logs
  - Tools: Fluentd, Logstash
  - References: KQL in Elastic SIEM, JSON/CEF log formats

---

- Security Tools Overview Learn:
  - SIEM: Splunk, QRadar
  - EDR: CrowdStrike
  - IDS/IPS: Snort
  - Vulnerability Scanners: Nessus
  - References: Splunk Free, Wazuh, Osquery, Nessus Essentials

---

- Basic Security Concepts Learn:
  - CIA Triad: Confidentiality, Integrity, Availability
  - Threat vs Vulnerability vs Risk
  - Defense-in-Depth, Zero Trust
  - References: Anki flashcards, Equifax breach case study

---

- Security Operations Workflow Learn:
  - Detection: Alerts from SIEM/EDR
  - Triage: Prioritize based on severity
  - Investigation: Correlate logs, hunt IOCs
  - Response: Containment, eradication
  - References: TheHive platform simulations

---

- Incident Response Basics Learn:
  - IR Lifecycle: Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned
  - References: NIST SP 800-61, tabletop exercises (ransomware scenario)

---

-  Documentation Standards Learn:
  - Incident reports, runbooks, SOPs, post-mortems
  - References: SANS Incident Handler’s Handbook

---

## Practical Application

1️⃣ Log Analysis Practice
  - Windows Event Viewer:
    - Filter for Event ID 4625 (failed login) or 7045 (new service creation)
    - Identify brute-force attacks from Security logs
  - Browser History Analysis:
    - Use Eric Zimmerman’s Tools to parse Chrome history for malicious URLs
  - Advanced Task:
    - Brute-Force Detection: Generate failed logins in your Windows VM (wrong password attempts)
    - Use Event Viewer to filter Event ID 4625 and export results to CSV
    - Zimmerman Tools Practice: Download LECmd and parse Chrome history from your VM
    - Look for visits to a test URL (e.g., http://test.com)
  - Tools:
    - Built-in: Windows Event Viewer, wevtutil CLI
    - Third-party: LogParser Lizard, Elastic SIEM

---

 2️⃣ Document Security Events
  - Create a template with fields:
    ```
    Date/Time          Source IP      Event ID   Description                      Action Taken
    YYYY-MM-DD HH:MM   192.168.x.x    4625       Multiple failed logins detected  User account locked
    ```
  - Practice documenting a mock event (e.g., “Multiple failed logins from 192.168.1.10”)

---

 3️⃣ Set Up Monitoring Dashboards
  - In Kibana or Grafana, create visualizations for:
    - Top 10 source IPs generating alerts
    - Frequency of critical Event IDs
  - Use pre-built dashboards (e.g., Sigma detection rules)

---

 4️⃣ Configure Alert Rules
  - In Elastic SIEM:
    - Rule: “Detect 5+ failed logins in 5 minutes”
    - Index: security-login-*
    - Condition: count > 5
    - Test: Simulate failed SSH logins
  - Advanced Task:
    - Custom Alert Rule: Create a rule in Wazuh to detect 3+ failed logins in 2 minutes
    - Test by attempting failed SSH logins (ssh user@192.168.1.x with wrong password)
    - Alert Validation: Verify alerts in the Wazuh dashboard and document the rule’s effectiveness

---

## Learning Approach

- Tools: Build a mini-SOC lab with Wazuh (SIEM) + Osquery (endpoint visibility)
- Process: Use MITRE ATT&CK to map alerts to adversary tactics (e.g., T1059 for PowerShell attacks)
- Outcome: Integrate practical exercises with theoretical knowledge for end-to-end SOC understanding

---

