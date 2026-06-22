# Suricata IDS — Installation and Configuration Guide
## Network Intrusion Detection for SOC Analysts

**Author:** Aigbokhaode Hope Imomoh — SOC Analyst
**Tool:** Suricata 7.x
**Target:** Ubuntu 22.04 (192.168.56.101)

---

## What is Suricata?

Suricata is an open-source Network Intrusion Detection and Prevention System (IDS/IPS). It monitors network traffic in real time and alerts on suspicious patterns using signature-based and anomaly-based detection.

**Key capabilities:**
- Real-time network traffic inspection
- Protocol identification and parsing
- File extraction from network traffic
- TLS/SSL certificate logging
- DNS, HTTP, SMB protocol logging
- Integration with Splunk and ELK

---

## Step 1 — Install Suricata on Ubuntu

```bash
sudo apt update
sudo apt install -y suricata
```

Verify installation:
```bash
suricata --version
```

---

## Step 2 — Update Suricata Rules

```bash
sudo suricata-update
```

This downloads the latest Emerging Threats ruleset. Expected output:
```
Loading /etc/suricata/suricata.yaml
Creating directory /var/lib/suricata/rules
Fetching https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz
  - 36964 rules downloaded
  - 0 rules disabled
  - 0 rules enabled
  - 0 rules modified
  - 0 rules reprocessed
Writing rules to /var/lib/suricata/rules/suricata.rules
```

---

## Step 3 — Configure Suricata

Edit the main configuration file:
```bash
sudo nano /etc/suricata/suricata.yaml
```

Key settings to configure:

### Set your network range:
```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.56.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
```

### Set the network interface to monitor:
```yaml
af-packet:
  - interface: enp0s8
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

### Enable logging:
```yaml
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - flow
```

---

## Step 4 — Start and Enable Suricata

```bash
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata
```

Expected output:
```
suricata.service - LSB: Next Generation IDS/IPS
   Loaded: loaded (/etc/init.d/suricata)
   Active: active (running)
```

---

## Step 5 — Test Suricata Detection

Run a test from Kali Linux to trigger Suricata alerts:

**From Kali (192.168.56.102):**
```bash
nmap -sV -p 1-1000 192.168.56.103
```

**Check Suricata alerts on Ubuntu:**
```bash
sudo tail -f /var/log/suricata/fast.log
```

Expected alert output:
```
06/22/2026-08:15:23.123456  [**] [1:2010935:3] ET SCAN Nmap Scripting Engine User-Agent Detected [**]
[Classification: Web Application Attack] [Priority: 1]
192.168.56.102:54321 -> 192.168.56.103:80
```

---

## Step 6 — Add Custom Rules

Create custom detection rules:
```bash
sudo nano /etc/suricata/rules/custom.rules
```

Add rules:
```
# Detect RDP brute force
alert tcp any any -> $HOME_NET 3389 (msg:"RDP Connection Attempt"; flow:to_server,established; threshold:type threshold, track by_src, count 10, seconds 60; sid:9000001; rev:1;)

# Detect Nmap scan
alert tcp any any -> $HOME_NET any (msg:"Nmap SYN Scan Detected"; flags:S; threshold:type threshold, track by_src, count 20, seconds 10; sid:9000002; rev:1;)

# Detect HTTP POST to suspicious URI
alert http any any -> any any (msg:"Suspicious HTTP POST to agent endpoint"; flow:to_server,established; content:"POST"; http_method; content:"/api/set_agent"; http_uri; sid:9000003; rev:1;)

# Detect .su TLD DNS query
alert dns any any -> any any (msg:"DNS Query to .su TLD - Suspicious"; dns.query; content:".su"; nocase; sid:9000004; rev:1;)
```

Load custom rules:
```bash
sudo suricata-update --no-reload
sudo systemctl restart suricata
```

---

## Step 7 — Suricata Lab Report

### Alerts Generated During Lab Testing

| Alert | Source | Destination | Count | Severity |
|---|---|---|---|---|
| ET SCAN Nmap Scan Detected | 192.168.56.102 | 192.168.56.103 | 47 | High |
| RDP Connection Attempts | 192.168.56.102 | 192.168.56.103:3389 | 423 | Critical |
| ET POLICY RDP Bruteforce | 192.168.56.102 | 192.168.56.103 | 1 | Critical |
| DNS Query to .su TLD | 192.168.56.103 | 8.8.8.8 | 23 | High |

### Key Finding
Suricata successfully detected:
- The Nmap reconnaissance scan from Kali Linux
- The Hydra RDP brute force attack (423 connection attempts)
- The C2 DNS queries to .su TLD domain

---

## Step 8 — Forward Suricata Logs to Splunk

Install Splunk Universal Forwarder on Ubuntu and add:

```bash
sudo nano /opt/splunkforwarder/etc/system/local/inputs.conf
```

Add:
```
[monitor:///var/log/suricata/eve.json]
disabled = false
index = suricata
sourcetype = suricata
```

Restart forwarder:
```bash
sudo /opt/splunkforwarder/bin/splunk restart
```

Query in Splunk:
```spl
index=suricata event_type=alert
| table _time, src_ip, dest_ip, dest_port, alert.signature, alert.severity
| sort - _time
```

---

**Author:** Aigbokhaode Hope Imomoh — SOC Analyst
**LinkedIn:** https://www.linkedin.com/in/aigbokhaode-hope-imomoh-962717393
**GitHub:** https://github.com/aigbokhaodehope7-create
