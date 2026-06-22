# Snort 3 Rules — Complete Writing Guide
## Network Intrusion Detection Rules for SOC Analysts

**Author:** Aigbokhaode Hope Imomoh — SOC Analyst
**Tool:** Snort 3 (Snort++)
**Purpose:** Network intrusion detection and prevention

---

## What is Snort 3?

Snort 3 (also called Snort++) is the latest major version of the world's most widely deployed open-source IDS/IPS. It is used by thousands of organisations worldwide and is the foundation for many commercial security products.

**Key differences from Snort 2:**
- Lua-based configuration (not .conf files)
- Multi-threaded packet processing
- Improved HTTP inspection engine
- Better performance on high-speed networks
- Simplified rule writing syntax

---

## Installing Snort 3 on Ubuntu

### Step 1 — Install dependencies
```bash
sudo apt update
sudo apt install -y build-essential libpcap-dev libpcre3-dev \
    libdumbnet-dev bison flex zlib1g-dev liblzma-dev \
    openssl libssl-dev pkg-config libhwloc-dev \
    cmake cpputest libsqlite3-dev uuid-dev libluajit-5.1-dev \
    libunwind-dev
```

### Step 2 — Install DAQ (Data Acquisition Library)
```bash
wget https://github.com/snort3/libdaq/archive/refs/tags/v3.0.13.tar.gz
tar xf v3.0.13.tar.gz
cd libdaq-3.0.13
./bootstrap
./configure
make
sudo make install
sudo ldconfig
```

### Step 3 — Download and compile Snort 3
```bash
wget https://github.com/snort3/snort3/archive/refs/tags/3.1.74.0.tar.gz
tar xf 3.1.74.0.tar.gz
cd snort3-3.1.74.0
./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
cd build
make -j$(nproc)
sudo make install
sudo ldconfig
```

### Step 4 — Verify installation
```bash
snort --version
```

Expected output:
```
   ,,_     -*> Snort++ <*-
  o"  )~   Version 3.1.74.0
   ''''    By Martin Roesch & The Snort Team
```

### Step 5 — Download community rules
```bash
sudo mkdir -p /etc/snort/rules
wget https://www.snort.org/downloads/community/snort3-community-rules.tar.gz
tar xf snort3-community-rules.tar.gz
sudo cp snort3-community-rules/snort3-community.rules /etc/snort/rules/
```

### Step 6 — Create Snort configuration
```bash
sudo nano /etc/snort/snort.lua
```

Basic configuration:
```lua
-- Network variables
HOME_NET = '192.168.56.0/24'
EXTERNAL_NET = '!$HOME_NET'

-- Path to rules
RULE_PATH = '/etc/snort/rules'

-- Include community rules
ips =
{
    enable_builtin_rules = true,
    include = RULE_PATH .. '/snort3-community.rules',
    rules = RULE_PATH .. '/soc-lab-custom.rules'
}

-- Output configuration
alert_fast =
{
    file = true,
    packet = false,
    limit = 10
}
```

### Step 7 — Test configuration
```bash
sudo snort -c /etc/snort/snort.lua --warn-all
```

### Step 8 — Run Snort
```bash
sudo snort -c /etc/snort/snort.lua -i enp0s8 -A alert_fast
```

---

## Snort 3 Rule Structure

Snort 3 rules follow a similar but slightly different format from Snort 2:

```
action proto src_ip src_port dir dst_ip dst_port ( options )
```

### Key differences from Snort 2:
- Sticky buffers replace modifier keywords
- `http_uri` is now a sticky buffer (not a modifier)
- Rules are more readable and modular

---

## Snort 3 Rule Components

### Actions

| Action | Description |
|---|---|
| `alert` | Generate alert and log packet |
| `drop` | Drop packet and alert (IPS mode) |
| `reject` | Drop and send reset |
| `pass` | Allow packet |
| `block` | Block and alert without reset |
| `rewrite` | Rewrite packet |

### Sticky Buffers (Snort 3)

| Buffer | Description |
|---|---|
| `http_uri` | HTTP URI |
| `http_method` | HTTP method |
| `http_header` | HTTP headers |
| `http_client_body` | HTTP request body |
| `http_server_body` | HTTP response body |
| `http_user_agent` | User-Agent header |
| `http_host` | Host header |
| `dns_query` | DNS query name |
| `tls_sni` | TLS Server Name Indication |

---

## Writing Snort 3 Rules — Step by Step

### Rule 1 — Detect RDP Brute Force

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (
    msg:"SOC-LAB SNORT3 RDP Brute Force Detected";
    flow:to_server;
    detection_filter:track by_src, count 10, seconds 60;
    classtype:attempted-admin;
    priority:1;
    sid:8000001;
    rev:1;
)
```

**Note:** In Snort 3, `detection_filter` replaces `threshold` for rate-based detection.

---

### Rule 2 — Detect Nmap Port Scan

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SOC-LAB SNORT3 Nmap SYN Scan Detected";
    flow:stateless;
    flags:S,12;
    detection_filter:track by_src, count 20, seconds 10;
    classtype:attempted-recon;
    priority:2;
    sid:8000002;
    rev:1;
)
```

---

### Rule 3 — Detect C2 Beaconing (Sticky Buffer Method)

**Snort 3 uses sticky buffers — much cleaner syntax:**

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SOC-LAB SNORT3 C2 Beaconing HTTP POST Detected";
    flow:to_server,established;
    http_method;
    content:"POST";
    http_uri;
    content:"/api/set_agent";
    classtype:trojan-activity;
    priority:1;
    sid:8000003;
    rev:1;
)
```

**Snort 3 sticky buffer explanation:**
- `http_uri;` sets the buffer to the HTTP URI
- `content:"/api/set_agent";` now matches within the URI buffer
- No need for `http_uri` modifier after content (as in Snort 2)

---

### Rule 4 — Detect DNS Query to Malicious Domain

```
alert dns $HOME_NET any -> any 53 (
    msg:"SOC-LAB SNORT3 DNS Query to Suspicious .su TLD";
    dns_query;
    content:".su";
    nocase;
    endswith;
    classtype:bad-unknown;
    priority:2;
    sid:8000004;
    rev:1;
)
```

---

### Rule 5 — Detect Cobalt Strike Beacon Pattern

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SOC-LAB SNORT3 Possible Cobalt Strike Beacon";
    flow:to_server,established;
    http_method;
    content:"POST";
    http_uri;
    content:"/api/";
    http_client_body;
    content:"|00 00 BE EF|";
    classtype:trojan-activity;
    priority:1;
    reference:url,www.cobaltstrike.com;
    sid:8000005;
    rev:1;
)
```

---

### Rule 6 — Detect SSH Brute Force

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
    msg:"SOC-LAB SNORT3 SSH Brute Force Attempt";
    flow:to_server;
    detection_filter:track by_src, count 5, seconds 30;
    classtype:attempted-admin;
    priority:1;
    sid:8000006;
    rev:1;
)
```

---

### Rule 7 — Detect SQL Injection Attempt

```
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"SOC-LAB SNORT3 SQL Injection Attempt Detected";
    flow:to_server,established;
    http_uri;
    content:"' OR '1'='1";
    nocase;
    classtype:web-application-attack;
    priority:1;
    sid:8000007;
    rev:1;
)
```

---

### Rule 8 — Detect Cross-Site Scripting (XSS)

```
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"SOC-LAB SNORT3 XSS Attack Detected";
    flow:to_server,established;
    http_client_body;
    content:"<script>";
    nocase;
    classtype:web-application-attack;
    priority:2;
    sid:8000008;
    rev:1;
)
```

---

### Rule 9 — Detect TLS Domain Fronting

```
alert tls $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SOC-LAB SNORT3 Possible TLS Domain Fronting";
    flow:to_server,established;
    tls_sni;
    content:"cloudflare.com";
    nocase;
    classtype:policy-violation;
    priority:2;
    sid:8000009;
    rev:1;
)
```

---

### Rule 10 — Detect Password in FTP

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (
    msg:"SOC-LAB SNORT3 FTP Cleartext Password Transmitted";
    flow:to_server,established;
    content:"PASS ";
    nocase;
    offset:0;
    depth:5;
    classtype:policy-violation;
    priority:2;
    sid:8000010;
    rev:1;
)
```

---

## Snort 3 vs Snort 2 — Key Differences

| Feature | Snort 2 | Snort 3 |
|---|---|---|
| Configuration | snort.conf | snort.lua (Lua) |
| Rule syntax | Modifier-based | Sticky buffer-based |
| Performance | Single-threaded | Multi-threaded |
| HTTP inspection | Limited | Full HTTP/2 support |
| Content matching | `content:"x"; http_uri;` | `http_uri; content:"x";` |
| Rate detection | `threshold:` | `detection_filter:` |
| TLS inspection | Limited | Full SNI/cert inspection |

---

## Snort 3 Rule Testing

### Test specific rules
```bash
sudo snort -c /etc/snort/snort.lua -r capture.pcap -A alert_fast
```

### Run against live interface
```bash
sudo snort -c /etc/snort/snort.lua -i enp0s8 -A alert_fast -l /var/log/snort/
```

### View alerts
```bash
sudo tail -f /var/log/snort/alert_fast.txt
```

### Validate rules only
```bash
sudo snort -c /etc/snort/snort.lua --warn-all -T
```

---

## Snort 3 SID Numbering Convention

| SID Range | Owner |
|---|---|
| 1 - 999 | Reserved by Snort team |
| 1000000 - 1999999 | Sourcefire/Cisco VRT |
| 2000000 - 2999999 | Emerging Threats |
| 3000000+ | User/local rules |
| 8000000+ | SOC Lab custom (this guide) |

---

**Author:** Aigbokhaode Hope Imomoh — SOC Analyst
**LinkedIn:** https://www.linkedin.com/in/aigbokhaode-hope-imomoh-962717393
**GitHub:** https://github.com/aigbokhaodehope7-create
