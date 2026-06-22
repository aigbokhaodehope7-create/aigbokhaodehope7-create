# Firewall Rules — Complete Writing Guide
## Windows Firewall and Linux iptables/UFW for SOC Analysts

**Author:** Aigbokhaode Hope Imomoh — SOC Analyst
**Tools:** Windows Defender Firewall, iptables, UFW (Uncomplicated Firewall)
**Environment:** SOC Home Lab

---

## Part 1 — Windows Defender Firewall Rules

### What is Windows Firewall?

Windows Defender Firewall is a host-based stateful firewall built into Windows. It filters inbound and outbound traffic based on rules you define.

**Key concepts:**
- **Inbound rules** — control traffic coming INTO the machine
- **Outbound rules** — control traffic going OUT of the machine
- **Profiles** — Domain, Private, Public (different rules for each)

---

### Method 1 — Windows Firewall GUI

#### Blocking an IP Address (Inbound)

1. Open **Windows Defender Firewall with Advanced Security**
2. Click **Inbound Rules** → **New Rule**
3. Select **Custom** → Next
4. Select **All programs** → Next
5. Protocol: **Any** → Next
6. Under **Remote IP addresses** → select **These IP addresses**
7. Add attacker IP: `192.168.56.102`
8. Click Next → select **Block the connection**
9. Check all profiles (Domain, Private, Public)
10. Name: `Block Attacker IP 192.168.56.102`
11. Click **Finish**

#### Blocking RDP from External Networks

1. Click **Inbound Rules** → **New Rule**
2. Select **Port** → Next
3. TCP, Specific port: `3389` → Next
4. **Block the connection** → Next
5. Select **Public** profile only
6. Name: `Block RDP from Public Network`

---

### Method 2 — PowerShell Firewall Rules

**Block inbound traffic from attacker IP:**
```powershell
New-NetFirewallRule `
    -DisplayName "Block Attacker 192.168.56.102" `
    -Direction Inbound `
    -Action Block `
    -RemoteAddress 192.168.56.102 `
    -Protocol Any `
    -Profile Any
```

**Block RDP from public networks:**
```powershell
New-NetFirewallRule `
    -DisplayName "Block RDP Public" `
    -Direction Inbound `
    -Action Block `
    -LocalPort 3389 `
    -Protocol TCP `
    -Profile Public
```

**Allow RDP only from trusted IP:**
```powershell
New-NetFirewallRule `
    -DisplayName "Allow RDP from SOC Analyst Only" `
    -Direction Inbound `
    -Action Allow `
    -LocalPort 3389 `
    -Protocol TCP `
    -RemoteAddress 192.168.56.101 `
    -Profile Any
```

**Block outbound traffic to C2 IP:**
```powershell
New-NetFirewallRule `
    -DisplayName "Block C2 Server Outbound" `
    -Direction Outbound `
    -Action Block `
    -RemoteAddress 185.234.0.0/16 `
    -Protocol Any `
    -Profile Any
```

**Block specific port outbound:**
```powershell
New-NetFirewallRule `
    -DisplayName "Block Outbound IRC C2" `
    -Direction Outbound `
    -Action Block `
    -RemotePort 6667,6668,6669 `
    -Protocol TCP `
    -Profile Any
```

**View all firewall rules:**
```powershell
Get-NetFirewallRule | Select-Object DisplayName, Direction, Action, Enabled
```

**Delete a rule:**
```powershell
Remove-NetFirewallRule -DisplayName "Block Attacker 192.168.56.102"
```

**Export all rules:**
```powershell
netsh advfirewall export "C:\firewall-backup.wfw"
```

---

### Method 3 — netsh Commands

**Block IP address:**
```cmd
netsh advfirewall firewall add rule name="Block Attacker" dir=in action=block remoteip=192.168.56.102
```

**Block port:**
```cmd
netsh advfirewall firewall add rule name="Block Port 4444" dir=in action=block protocol=tcp localport=4444
```

**Allow specific application:**
```cmd
netsh advfirewall firewall add rule name="Allow Splunk" dir=in action=allow program="C:\Program Files\Splunk\bin\splunkd.exe"
```

**Show all rules:**
```cmd
netsh advfirewall firewall show rule name=all
```

---

### Windows Firewall — SOC Lab Rules Applied

| Rule Name | Direction | Action | Details | Reason |
|---|---|---|---|---|
| Block Attacker IP | Inbound | Block | Source: 192.168.56.102 | Block Kali after attack confirmed |
| Block RDP Public | Inbound | Block | Port 3389, Public profile | Prevent external RDP |
| Allow RDP SIEM | Inbound | Allow | Port 3389, Source: 192.168.56.101 | Allow only SIEM access |
| Block C2 Outbound | Outbound | Block | Dest: 185.234.0.0/16 | Block C2 server range |
| Block IRC C2 | Outbound | Block | Ports 6667-6669 | Block IRC C2 channels |
| Block FTP Cleartext | Outbound | Block | Port 21 | Force SFTP instead |

---

## Part 2 — Linux iptables Rules (Ubuntu)

### What is iptables?

iptables is the Linux kernel firewall. It uses tables and chains to filter packets:

- **INPUT chain** — incoming packets to the machine
- **OUTPUT chain** — outgoing packets from the machine
- **FORWARD chain** — packets being routed through the machine

**Targets:**
- `ACCEPT` — allow the packet
- `DROP` — silently drop the packet
- `REJECT` — drop and send error response
- `LOG` — log the packet

---

### Basic iptables Syntax

```
iptables -[A/I/D] [CHAIN] [options] -j [TARGET]
```

| Flag | Meaning |
|---|---|
| `-A` | Append rule to chain |
| `-I` | Insert rule at position |
| `-D` | Delete rule |
| `-L` | List all rules |
| `-F` | Flush (delete all) rules |
| `-n` | Numeric output (no DNS lookup) |
| `-v` | Verbose output |
| `-p` | Protocol (tcp, udp, icmp) |
| `-s` | Source IP |
| `-d` | Destination IP |
| `--sport` | Source port |
| `--dport` | Destination port |

---

### iptables Rules — Step by Step

**View current rules:**
```bash
sudo iptables -L -n -v
```

**Allow established connections:**
```bash
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
```

**Allow loopback:**
```bash
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
```

**Allow SSH from trusted IP only:**
```bash
sudo iptables -A INPUT -p tcp -s 192.168.56.101 --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j DROP
```

**Allow Splunk web interface:**
```bash
sudo iptables -A INPUT -p tcp -s 192.168.56.0/24 --dport 8000 -j ACCEPT
```

**Allow Splunk forwarder:**
```bash
sudo iptables -A INPUT -p tcp -s 192.168.56.103 --dport 9997 -j ACCEPT
```

**Block attacker IP:**
```bash
sudo iptables -A INPUT -s 192.168.56.102 -j DROP
```

**Block outbound to C2 server:**
```bash
sudo iptables -A OUTPUT -d 185.234.0.0/16 -j DROP
```

**Block outbound IRC C2 ports:**
```bash
sudo iptables -A OUTPUT -p tcp --dport 6667 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 6668 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 6669 -j DROP
```

**Log dropped packets:**
```bash
sudo iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
sudo iptables -A INPUT -j DROP
```

**Block port scanning:**
```bash
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
sudo iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
```

**Rate limit SSH connections:**
```bash
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
```

**Save iptables rules:**
```bash
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

---

## Part 3 — UFW (Uncomplicated Firewall) Rules

### What is UFW?

UFW is a simplified interface for iptables, making firewall management easier on Ubuntu systems.

### Enable UFW
```bash
sudo ufw enable
sudo ufw status verbose
```

### Basic UFW Rules

**Allow SSH:**
```bash
sudo ufw allow ssh
# or
sudo ufw allow 22/tcp
```

**Allow Splunk web interface:**
```bash
sudo ufw allow from 192.168.56.0/24 to any port 8000
```

**Allow Splunk forwarder:**
```bash
sudo ufw allow from 192.168.56.103 to any port 9997
```

**Block attacker IP:**
```bash
sudo ufw deny from 192.168.56.102 to any
```

**Allow only from specific IP:**
```bash
sudo ufw allow from 192.168.56.101 to any port 22
sudo ufw deny 22
```

**Block specific port:**
```bash
sudo ufw deny 23/tcp
sudo ufw deny 21/tcp
```

**Block outbound to C2:**
```bash
sudo ufw deny out to 185.234.0.0/16
```

**Allow HTTP and HTTPS:**
```bash
sudo ufw allow http
sudo ufw allow https
```

**Delete a rule:**
```bash
sudo ufw delete deny from 192.168.56.102
```

**View rules with numbers:**
```bash
sudo ufw status numbered
```

**Delete rule by number:**
```bash
sudo ufw delete 3
```

---

### UFW SOC Lab Configuration

Full UFW setup for Ubuntu SIEM server:

```bash
# Reset to defaults
sudo ufw --force reset

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow loopback
sudo ufw allow in on lo

# Allow SSH from lab network only
sudo ufw allow from 192.168.56.0/24 to any port 22

# Allow Splunk web interface from lab network
sudo ufw allow from 192.168.56.0/24 to any port 8000

# Allow Splunk forwarder from Windows 10 target
sudo ufw allow from 192.168.56.103 to any port 9997

# Allow Suricata monitoring (no ports needed)

# Block attacker after confirmed attack
sudo ufw deny from 192.168.56.102 to any

# Enable firewall
sudo ufw enable

# Verify
sudo ufw status verbose
```

---

## Firewall Rule Best Practices

| Practice | Reason |
|---|---|
| Default deny all inbound | Block everything unless explicitly allowed |
| Allow only required ports | Minimise attack surface |
| Restrict by source IP | Only allow known/trusted sources |
| Log dropped packets | Visibility into blocked attempts |
| Rate limit authentication ports | Prevent brute force |
| Block outbound to known bad IPs | Prevent C2 communication |
| Review rules regularly | Remove stale rules |
| Test rules after changes | Confirm intended behaviour |

---

## SOC Lab Firewall Report

### Rules Applied After Brute Force Attack

| Machine | Tool | Rule Applied | Result |
|---|---|---|---|
| Windows 10 | PowerShell | Block inbound from 192.168.56.102 | Attacker blocked |
| Windows 10 | PowerShell | Block RDP from Public profile | External RDP blocked |
| Ubuntu | UFW | Deny from 192.168.56.102 | Attacker blocked at SIEM |
| Ubuntu | UFW | Allow only 192.168.56.103 on port 9997 | Log forwarding secured |
| Ubuntu | iptables | Rate limit SSH to 3 attempts/60 sec | SSH brute force prevented |

---

**Author:** Aigbokhaode Hope Imomoh — SOC Analyst
**LinkedIn:** https://www.linkedin.com/in/aigbokhaode-hope-imomoh-962717393
**GitHub:** https://github.com/aigbokhaodehope7-create
