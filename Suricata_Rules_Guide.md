# Suricata Rules — Complete Writing Guide
## Network Detection Rules for SOC Analysts

**Author:** Aigbokhaode Hope Imomoh — SOC Analyst
**Tool:** Suricata 7.x
**Environment:** SOC Home Lab — Ubuntu 22.04

---

## Understanding Suricata Rule Structure

Every Suricata rule follows this exact format:

```
action protocol src_ip src_port direction dst_ip dst_port (options)
```

### Full Example:
```
alert tcp 192.168.56.102 any -> 192.168.56.103 3389 (msg:"RDP Brute Force Detected"; threshold:type threshold, track by_src, count 10, seconds 60; sid:9000001; rev:1;)
```

---

## Rule Components Explained

### 1. Action

| Action | Description |
|---|---|
| `alert` | Generate an alert and log the packet |
| `drop` | Drop the packet and generate alert (IPS mode) |
| `reject` | Drop and send TCP reset or ICMP error |
| `pass` | Allow the packet and stop processing |
| `log` | Log the packet without alerting |

### 2. Protocol

| Protocol | Use Case |
|---|---|
| `tcp` | TCP traffic (HTTP, RDP, SSH, FTP) |
| `udp` | UDP traffic (DNS, DHCP, NTP) |
| `icmp` | ICMP traffic (ping, traceroute) |
| `http` | HTTP application layer |
| `dns` | DNS queries and responses |
| `tls` | TLS/SSL encrypted traffic |
| `smb` | SMB file sharing protocol |
| `ssh` | SSH traffic |
| `ftp` | FTP traffic |

### 3. Source and Destination

| Variable | Meaning |
|---|---|
| `any` | Match any IP address or port |
| `$HOME_NET` | Your internal network (defined in suricata.yaml) |
| `$EXTERNAL_NET` | Everything outside HOME_NET |
| `$HTTP_PORTS` | Standard HTTP ports (80, 8080, etc.) |
| `$SQL_PORTS` | Database ports |
| `[1:1024]` | Port range 1 to 1024 |
| `!192.168.1.1` | NOT this IP address |
| `[192.168.1.0/24,10.0.0.0/8]` | Multiple networks |

### 4. Direction

| Symbol | Meaning |
|---|---|
| `->` | Traffic from source to destination |
| `<>` | Bidirectional traffic |

---

## Rule Options Explained

### Essential Options

| Option | Syntax | Description |
|---|---|---|
| `msg` | `msg:"Alert description";` | Human-readable alert message |
| `sid` | `sid:1000001;` | Unique rule ID number |
| `rev` | `rev:1;` | Rule revision number |
| `content` | `content:"GET";` | Match specific string in payload |
| `nocase` | `content:"get"; nocase;` | Case-insensitive matching |
| `flow` | `flow:to_server,established;` | Match traffic direction and state |
| `threshold` | `threshold:type threshold, track by_src, count 10, seconds 60;` | Rate limiting |
| `classtype` | `classtype:attempted-recon;` | Rule classification |
| `priority` | `priority:1;` | Alert priority (1=highest) |
| `reference` | `reference:cve,2021-34527;` | CVE or external reference |

### Content Matching Options

| Option | Description |
|---|---|
| `content:"string"` | Match exact string |
| `content:"\|FF D8\|"` | Match hex bytes |
| `nocase` | Ignore case |
| `offset:5` | Start matching at byte 5 |
| `depth:10` | Only match within first 10 bytes |
| `distance:3` | Start next content 3 bytes after previous |
| `within:10` | Next content must be within 10 bytes |
| `rawbytes` | Match raw packet bytes |
| `fast_pattern` | Use this content for fast pattern matching |

### HTTP-Specific Options

| Option | Description |
|---|---|
| `http_method` | Match HTTP method (GET, POST) |
| `http_uri` | Match the URI |
| `http_header` | Match HTTP headers |
| `http_client_body` | Match HTTP request body |
| `http_server_body` | Match HTTP response body |
| `http_user_agent` | Match User-Agent header |
| `http_host` | Match Host header |
| `http_stat_code` | Match HTTP status code |

### DNS-Specific Options

| Option | Description |
|---|---|
| `dns.query` | Match DNS query name |
| `dns.answer` | Match DNS answer |
| `dns.opcode` | Match DNS operation code |

### Flow Options

| Option | Description |
|---|---|
| `flow:to_server` | Traffic going to server |
| `flow:to_client` | Traffic going to client |
| `flow:established` | Only established connections |
| `flow:not_established` | Only new connections |

---

## Writing Rules — Step by Step

### Rule 1 — Detect RDP Brute Force

**Goal:** Alert when a single IP makes more than 10 RDP connection attempts in 60 seconds.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (
    msg:"SOC-LAB RDP Brute Force Detected";
    flow:to_server;
    threshold:type threshold, track by_src, count 10, seconds 60;
    classtype:attempted-admin;
    priority:1;
    sid:9000001;
    rev:1;
)
```

**Breakdown:**
- `alert tcp` — generate alert on TCP traffic
- `$EXTERNAL_NET any` — from any external IP, any port
- `-> $HOME_NET 3389` — going to our network on port 3389 (RDP)
- `threshold` — trigger only after 10 connections in 60 seconds
- `priority:1` — highest priority alert

---

### Rule 2 — Detect Nmap Port Scan

**Goal:** Detect SYN port scanning from a single source.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SOC-LAB Nmap SYN Port Scan Detected";
    flow:stateless;
    flags:S,12;
    threshold:type threshold, track by_src, count 20, seconds 10;
    classtype:attempted-recon;
    priority:2;
    reference:url,nmap.org;
    sid:9000002;
    rev:1;
)
```

**Breakdown:**
- `flags:S,12` — match SYN flag only (not SYN-ACK)
- `threshold` — trigger after 20 SYN packets in 10 seconds
- `classtype:attempted-recon` — reconnaissance classification

---

### Rule 3 — Detect C2 Beaconing via HTTP POST

**Goal:** Alert on HTTP POST requests to suspicious C2 endpoints.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SOC-LAB Possible C2 Beaconing HTTP POST";
    flow:to_server,established;
    content:"POST";
    http_method;
    content:"/api/set_agent";
    http_uri;
    classtype:trojan-activity;
    priority:1;
    sid:9000003;
    rev:1;
)
```

**Breakdown:**
- `http` protocol — application layer detection
- `content:"POST"; http_method` — match HTTP POST method
- `content:"/api/set_agent"; http_uri` — match specific URI
- `classtype:trojan-activity` — malware classification

---

### Rule 4 — Detect DNS Query to Suspicious TLD

**Goal:** Alert on DNS queries to known malicious TLDs.

```
alert dns $HOME_NET any -> any 53 (
    msg:"SOC-LAB DNS Query to Suspicious TLD .su";
    dns.query;
    content:".su";
    nocase;
    endswith;
    classtype:bad-unknown;
    priority:2;
    sid:9000004;
    rev:1;
)
```

**For multiple TLDs, use multiple rules:**
```
alert dns $HOME_NET any -> any 53 (msg:"SOC-LAB DNS Query .tk TLD"; dns.query; content:".tk"; nocase; endswith; sid:9000005; rev:1;)
alert dns $HOME_NET any -> any 53 (msg:"SOC-LAB DNS Query .ml TLD"; dns.query; content:".ml"; nocase; endswith; sid:9000006; rev:1;)
alert dns $HOME_NET any -> any 53 (msg:"SOC-LAB DNS Query .cf TLD"; dns.query; content:".cf"; nocase; endswith; sid:9000007; rev:1;)
```

---

### Rule 5 — Detect FTP Cleartext Credentials

**Goal:** Alert when FTP credentials are sent in cleartext.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (
    msg:"SOC-LAB FTP Cleartext Credentials Detected";
    flow:to_server,established;
    content:"PASS ";
    nocase;
    classtype:policy-violation;
    priority:2;
    sid:9000008;
    rev:1;
)
```

---

### Rule 6 — Detect SSH Brute Force

**Goal:** Alert on multiple SSH connection attempts.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
    msg:"SOC-LAB SSH Brute Force Attempt";
    flow:to_server;
    threshold:type threshold, track by_src, count 5, seconds 30;
    classtype:attempted-admin;
    priority:1;
    sid:9000009;
    rev:1;
)
```

---

### Rule 7 — Detect ICMP Tunneling

**Goal:** Alert on large ICMP packets that may indicate tunneling.

```
alert icmp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SOC-LAB Possible ICMP Tunneling - Large Payload";
    itype:8;
    dsize:>64;
    classtype:bad-unknown;
    priority:2;
    sid:9000010;
    rev:1;
)
```

---

### Rule 8 — Detect Suspicious PowerShell Download

**Goal:** Detect PowerShell downloading content over HTTP.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SOC-LAB PowerShell HTTP Download Detected";
    flow:to_server,established;
    content:"PowerShell";
    http_user_agent;
    nocase;
    classtype:trojan-activity;
    priority:1;
    sid:9000011;
    rev:1;
)
```

---

### Rule 9 — Detect SMB Exploitation Attempt

**Goal:** Detect EternalBlue/SMB exploitation attempts.

```
alert smb $EXTERNAL_NET any -> $HOME_NET 445 (
    msg:"SOC-LAB Possible SMB Exploitation Attempt";
    flow:to_server,established;
    classtype:attempted-admin;
    priority:1;
    reference:cve,2017-0144;
    sid:9000012;
    rev:1;
)
```

---

### Rule 10 — Detect Data Exfiltration via Large Upload

**Goal:** Alert on unusually large HTTP POST uploads.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SOC-LAB Large HTTP Upload Possible Exfiltration";
    flow:to_server,established;
    content:"POST";
    http_method;
    dsize:>1000000;
    classtype:policy-violation;
    priority:2;
    sid:9000013;
    rev:1;
)
```

---

## How to Load Your Custom Rules

### Step 1 — Create rules file
```bash
sudo nano /etc/suricata/rules/soc-lab-custom.rules
```

### Step 2 — Add rules file to suricata.yaml
```bash
sudo nano /etc/suricata/suricata.yaml
```
Find the `rule-files` section and add:
```yaml
rule-files:
  - suricata.rules
  - soc-lab-custom.rules
```

### Step 3 — Validate rules
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```
Expected output: `Configuration provided was successfully loaded. Exiting.`

### Step 4 — Reload Suricata
```bash
sudo systemctl restart suricata
```

### Step 5 — Monitor alerts
```bash
sudo tail -f /var/log/suricata/fast.log
```

---

## Rule Testing Checklist

| Rule | Test Method | Expected Alert |
|---|---|---|
| RDP Brute Force | Run Hydra from Kali | SOC-LAB RDP Brute Force Detected |
| Port Scan | Run Nmap from Kali | SOC-LAB Nmap SYN Port Scan Detected |
| C2 Beaconing | Curl POST to test endpoint | SOC-LAB Possible C2 Beaconing |
| DNS Suspicious TLD | nslookup test.su | SOC-LAB DNS Query to Suspicious TLD |
| SSH Brute Force | Run Hydra SSH from Kali | SOC-LAB SSH Brute Force Attempt |

---

**Author:** Aigbokhaode Hope Imomoh — SOC Analyst
**LinkedIn:** https://www.linkedin.com/in/aigbokhaode-hope-imomoh-962717393
**GitHub:** https://github.com/aigbokhaodehope7-create
