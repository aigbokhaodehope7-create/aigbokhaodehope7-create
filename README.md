# Aigbokhaode Hope Imomoh

### SOC Analyst | Threat Detection | Incident Response | Blue Team Security

Location: Abuja, Nigeria | Phone: +234 911 656 6020 | Available Immediately (Remote / Hybrid / On-site)

LinkedIn: https://www.linkedin.com/in/aigbokhaode-hope-imomoh-962717393
Email: aigbokhaodehope7@gmail.com
GitHub: https://github.com/aigbokhaodehope7-create

---

## About Me

I am a cybersecurity professional specialising in Security Operations Centre (SOC) analysis, threat detection, and incident response. I completed a structured 8-module, 12-week SOC Analyst Internship Programme and a parallel 6-module, 6-week Incident Response and Threat Hunting Intensive, during which I designed and operated a fully functional multi-VM home lab replicating a real enterprise SOC environment.

My work is hands-on, evidence-based, and mapped directly to the MITRE ATT&CK framework.

- Completed 8-module SOC Analyst Internship covering Networking, SIEM, Threat Hunting, IR, and Vulnerability Management
- Built and operated a multi-VM home lab: Windows 10 + Ubuntu/Splunk SIEM + Kali Linux
- Actively pursuing CompTIA Security+ (SY0-701)
- Open to SOC Analyst Tier-1/Tier-2 roles and internships — remote, hybrid, or on-site
- Built entire SOC lab from scratch, ran live attacks against it, detected and documented every step
## Technical Skills

| Category | Tools and Technologies |
|---|---|
| SIEM and Log Management | Splunk Enterprise, SPL query authoring, Universal Forwarder, alert correlation, dashboards |
| Host Telemetry | Sysmon v15.20, Windows Event Logs (4624/4625/4688/4698/7045), PowerShell logging |
| Network Analysis | Wireshark, PCAP analysis, Suricata IDS, Nmap, TCP/IP, DNS, HTTP/S |
| Threat Frameworks | MITRE ATT&CK, PICERL Incident Response Lifecycle, Cyber Kill Chain |
| Digital Forensics | Volatility memory analysis, Windows Event Viewer, log timeline reconstruction |
| Vulnerability Management | Nessus Expert, vulnerability scanning, risk prioritisation |
| Attack Simulation | Hydra brute force, Nmap reconnaissance, Kali Linux toolset |
| Operating Systems | Windows 10/Server, Ubuntu Linux, Kali Linux, VirtualBox |
| Scripting and Reporting | Python fundamentals, Bash basic automation, incident report writing |

---

## Internship Programme — Modules Completed

### SOC Analyst Internship Programme (8 Modules — 12 Weeks)

| Module | Topic | Key Skills Gained |
|---|---|---|
| Module 1 | Networking Fundamentals | TCP/IP, DNS, HTTP/S, OSI model, packet flow |
| Module 2 | Security Fundamentals | CIA triad, threat landscape, attack types, defence strategies |
| Module 3 | SIEM and Splunk | Splunk deployment, SPL queries, dashboards, alert creation |
| Module 4 | Windows Log Analysis | Event IDs, Sysmon configuration, log forwarding, forensic triage |
| Module 5 | Network Traffic Analysis | Wireshark, PCAP analysis, protocol dissection, anomaly detection |
| Module 6 | Incident Response | PICERL lifecycle, IR playbooks, containment, eradication, reporting |
| Module 7 | Threat Hunting and MITRE ATT&CK | TTP mapping, proactive hunting, hypothesis-driven investigation |
| Module 8 | Vulnerability Management | Nessus scanning, CVSS scoring, risk prioritisation, remediation planning |

### Incident Response, Threat Hunting and MITRE ATT&CK Intensive (6 Modules — 6 Weeks)

| Module | Topic | Key Skills Gained |
|---|---|---|
| Module 1 | IR Foundations | IR team roles, escalation procedures, runbook usage |
| Module 2 | Threat Intelligence | IOC analysis, threat actor profiling, intelligence-driven defence |
| Module 3 | MITRE ATT&CK Deep Dive | Tactic and technique mapping, ATT&CK Navigator, adversary emulation |
| Module 4 | Advanced Threat Hunting | Hypothesis building, SPL hunting queries, behavioural analytics |
| Module 5 | Digital Forensics | Memory analysis with Volatility, artefact collection, chain of custody |
| Module 6 | Capstone — Full IR Simulation | End-to-end incident simulation, report writing, lessons-learned debrief |

---## Hands-On Projects

### SOC Home Lab — Full Environment Build

Built a production-grade SOC home lab from scratch using VirtualBox.

| Component | Details |
|---|---|
| Attacker VM | Kali Linux |
| Target VM | Windows 10 — 192.168.56.103 |
| SIEM VM | Ubuntu 22.04 + Splunk Enterprise — 192.168.56.101 |
| Host Telemetry | Sysmon v15.20 with custom XML config |
| Log Forwarding | Splunk Universal Forwarder — Windows Security, System, Sysmon, PowerShell, Defender |
| Events Ingested | 5,900+ security events |
| IDS | Suricata deployed on Ubuntu for network-layer detection |

---

### RDP Brute Force Attack — Detection and MITRE ATT&CK Mapping

Simulated a real RDP brute-force attack and detected it end-to-end in Splunk.

| Detail | Value |
|---|---|
| Attack Tool | Hydra (Kali Linux) |
| Target Account | Local account "Hope" — port 3389, NLA disabled |
| Detection | SPL correlation: EventCode 4625 (failed) to 4624 (successful login) |
| MITRE ATT&CK | T1110 Brute Force, T1021.001 RDP, T1595 Reconnaissance, T1556 Credential Access |
| Deliverable | Formal incident response report with evidence chain, IOCs, and remediation |

SPL Detection Query:index=wineventlog EventCode=4625
| stats count by src_ip, user, _time
| where count > 5
| join src_ip [search index=wineventlog EventCode=4624]
| table src_ip, user, count, _time
---

### Malware Traffic Analysis — PCAP Investigation

Identified Cobalt Strike C2 beaconing from 48,877 packets of raw network traffic.

| Detail | Value |
|---|---|
| Packet Count | 48,877 packets |
| Tool | Wireshark |
| Finding | Cobalt Strike C2 via Cloudflare-fronted infrastructure |
| C2 Indicator | HTTP POST requests to /api/set_agent endpoint |
| Additional IOCs | Beaconing intervals, HTTP header anomalies, .su TLD C2 domain |
| Deliverable | IOC report, TTP documentation, LinkedIn writeup |

---

### Windows Event Log Forensics

Reconstructed full attacker timeline from Windows logs after a simulated intrusion.

- Investigated Windows Security, System, Application, and PowerShell event logs
- Correlated Sysmon process-creation EventCode 4688 and network-connection events
- Identified lateral movement and persistence indicators across the kill chain
- Produced a structured forensic timeline report with full evidence chain and remediation steps

---

### Network IDS — Suricata Deployment and Tuning

Deployed layered network-level detection alongside host-based Sysmon telemetry.

- Installed and configured Suricata IDS on Ubuntu Linux
- Tuned detection rules and validated against live Nmap reconnaissance scans from Kali Linux
- Cross-referenced Suricata network alerts with Wireshark PCAP captures for IOC confirmation

---

### Vulnerability Assessment — Nessus Expert

Conducted vulnerability scanning and risk assessment as part of Module 8.

- Configured Nessus Expert on Kali Linux for network vulnerability scanning
- Performed credentialed and uncredentialed scans against lab targets
- Prioritised findings using CVSS scoring and produced a remediation report

---

### Portfolio Artefacts Produced

| Document | Description |
|---|---|
| SOC Lab Setup Summary | Full documentation of home lab build and configuration |
| Brute Force Attack Report | Incident report with MITRE ATT&CK mapping and IOC evidence |
| Windows Firewall Guide | Hardening guide for Windows firewall configuration |
| Wireshark IR Guide | Step-by-step Wireshark usage guide for incident response |
| Splunk SPL Operations Guide | Reference guide for common SOC SPL queries |
| PCAP Malware Analysis Report | Full malware traffic analysis with LinkedIn writeup |

---## Home Lab Architecture
+------------------------------------------------------+
|                  VirtualBox Home Lab                 |
|                                                      |
|   +-------------+          +----------------------+  |
|   |  Kali Linux |--------->|  Windows 10 Target   |  |
|   |  (Attacker) |  Attack  |  192.168.56.103      |  |
|   |  Hydra/Nmap |          |  Sysmon v15 + UF     |  |
|   +-------------+          +----------+-----------+  |
|                                       | Forwards logs |
|                                       v               |
|                        +-------------------------+   |
|                        |   Ubuntu / Splunk SIEM  |   |
|                        |   192.168.56.101        |   |
|                        |   Suricata IDS          |   |
|                        +-------------------------+   |
+------------------------------------------------------+

------

## Certifications and Training

| Certification | Issuer | Status | Year |
|---|---|---|---|
| SOC Analyst Internship Programme (8-module, 12-week) | Claude SOC Lab Program | Completed | 2026 |
| Incident Response, Threat Hunting and MITRE ATT&CK Intensive (6-module) | Claude SOC Lab Program | Completed | 2026 |
| Cybersecurity Training | Neocloud Technology, Abuja | Completed | 2025 |
| CompTIA Security+ SY0-701 | CompTIA | In Progress | 2026 |

---

## Education

| Qualification | Institution |
|---|---|
| Higher National Diploma (HND) | Federal Polytechnic Nasarawa |
| National Diploma (ND) | Isa Mustapha Agwai Polytechnic, Lafia |

---

## What I Bring to a SOC Team

- Hands-on experience writing and tuning SPL queries for real threat detection
- Completed the full incident response lifecycle (PICERL) on simulated attacks
- Proven ability to map findings to MITRE ATT&CK tactics and techniques
- Skilled at producing professional incident reports with evidence chains
- Experience with both host-based (Sysmon) and network-based (Suricata) detection
- Conducted real vulnerability assessments using Nessus Expert
- Self-driven — built an entire SOC environment independently from scratch
- Strong documentation, communication, and reporting skills
- Fast learner, available immediately, eager to contribute from day one

---

## Repository Index

| Repository | Description | Topics |
|---|---|---|
| Malware_Analysis.txt | Cobalt Strike C2 PCAP investigation report | malware-analysis, wireshark, threat-hunting, pcap |
| SOC-Home-Lab (coming soon) | SPL queries, Sysmon config XML, IR reports | splunk, siem, sysmon, incident-response |
| calculator.py | Python scripting fundamentals | python |

---

## Connect With Me

- LinkedIn: https://www.linkedin.com/in/aigbokhaode-hope-imomoh-962717393
- Email: aigbokhaodehope7@gmail.com
- GitHub: https://github.com/aigbokhaodehope7-create

---

"Security is not a product, it is a process." — Bruce Schneier
