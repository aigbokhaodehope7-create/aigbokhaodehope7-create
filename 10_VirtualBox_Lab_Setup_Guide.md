# VirtualBox SOC Home Lab — Complete Setup Guide
## Installing Ubuntu, Windows 10 and Kali Linux

**Author:** Aigbokhaode Hope Imomoh — SOC Analyst
**Tool:** Oracle VirtualBox 7.x
**Purpose:** Build a fully operational SOC home lab environment

---

## Overview

This guide documents the complete setup of a 3-VM SOC home lab using VirtualBox. The lab replicates a real enterprise SOC environment with an attacker machine, a target machine, and a SIEM server.

```
+--------------------------------------------------+
|              VirtualBox Host Machine             |
|                                                  |
|  +------------+   +------------+  +----------+  |
|  | Kali Linux |   | Windows 10 |  |  Ubuntu  |  |
|  | Attacker   |   | Target     |  |  SIEM    |  |
|  | .102       |   | .103       |  |  .101    |  |
|  +------------+   +------------+  +----------+  |
|                                                  |
|         Host-Only Network: 192.168.56.0/24       |
+--------------------------------------------------+
```

---

## Step 1 — Install VirtualBox

1. Go to https://www.virtualbox.org/wiki/Downloads
2. Download VirtualBox for your host OS (Windows/Linux/Mac)
3. Run the installer and follow the prompts
4. Also download and install the **VirtualBox Extension Pack**
5. Verify installation — open VirtualBox and confirm it launches

---

## Step 2 — Configure Host-Only Network

Before creating VMs, set up the network all VMs will share:

1. Open VirtualBox
2. Go to **File > Host Network Manager**
3. Click **Create**
4. Set IP address: `192.168.56.1`
5. Set Subnet Mask: `255.255.255.0`
6. Disable DHCP server (we will assign static IPs manually)
7. Click **Apply**

---

## Step 3 — Install Ubuntu 22.04 (Splunk SIEM)

### 3.1 Download Ubuntu
- Download Ubuntu 22.04 LTS ISO from https://ubuntu.com/download/desktop

### 3.2 Create the VM
1. Click **New** in VirtualBox
2. Name: `Ubuntu-SIEM`
3. Type: Linux
4. Version: Ubuntu (64-bit)
5. RAM: **4096 MB (4GB minimum)**
6. Storage: **50GB** (create new virtual hard disk)
7. Click **Create**

### 3.3 Configure VM Settings
1. Select the VM → click **Settings**
2. Go to **Network**:
   - Adapter 1: NAT (for internet access)
   - Adapter 2: Host-only Adapter → select your host-only network
3. Go to **Storage** → attach Ubuntu ISO to optical drive
4. Click **OK**

### 3.4 Install Ubuntu
1. Start the VM
2. Select **Install Ubuntu**
3. Choose language and keyboard layout
4. Select **Minimal Installation**
5. Choose **Erase disk and install Ubuntu**
6. Set username: `soc-analyst`
7. Set a strong password
8. Complete installation and restart

### 3.5 Configure Static IP
After installation, open Terminal:
```bash
sudo nano /etc/netplan/00-installer-config.yaml
```
Add:
```yaml
network:
  version: 2
  ethernets:
    enp0s8:
      addresses: [192.168.56.101/24]
      dhcp4: no
```
Apply:
```bash
sudo netplan apply
```
Verify:
```bash
ip addr show
ping 192.168.56.1
```

---

## Step 4 — Install Windows 10 (Target Machine)

### 4.1 Download Windows 10
- Download Windows 10 ISO from https://www.microsoft.com/software-download/windows10

### 4.2 Create the VM
1. Click **New** in VirtualBox
2. Name: `Windows10-Target`
3. Type: Microsoft Windows
4. Version: Windows 10 (64-bit)
5. RAM: **2048 MB (2GB)**
6. Storage: **50GB**
7. Click **Create**

### 4.3 Configure VM Settings
1. Select VM → **Settings**
2. **Network**:
   - Adapter 1: NAT
   - Adapter 2: Host-only Adapter
3. Attach Windows 10 ISO to optical drive

### 4.4 Install Windows 10
1. Start the VM
2. Select language and click **Install Now**
3. Select **Windows 10 Pro**
4. Choose **Custom: Install Windows only**
5. Select the virtual disk and install
6. Set up a local account (no Microsoft account needed)
7. Username: `Hope`
8. Set password

### 4.5 Configure Static IP
1. Open **Control Panel > Network and Internet > Network Connections**
2. Right-click the host-only adapter → **Properties**
3. Select **Internet Protocol Version 4 (TCP/IPv4)** → **Properties**
4. Set:
   - IP: `192.168.56.103`
   - Subnet: `255.255.255.0`
   - Gateway: `192.168.56.1`
5. Click **OK**

### 4.6 Enable RDP (for lab attack simulation)
1. Right-click **This PC** → **Properties**
2. Click **Remote settings**
3. Select **Allow remote connections to this computer**
4. Uncheck **Allow connections only from computers running NLA** (for lab purposes)
5. Click **OK**

---

## Step 5 — Install Kali Linux (Attacker Machine)

### 5.1 Download Kali Linux
- Download Kali Linux ISO from https://www.kali.org/get-kali/

### 5.2 Create the VM
1. Click **New** in VirtualBox
2. Name: `Kali-Attacker`
3. Type: Linux
4. Version: Debian (64-bit)
5. RAM: **2048 MB**
6. Storage: **30GB**
7. Click **Create**

### 5.3 Configure VM Settings
1. Select VM → **Settings**
2. **Network**:
   - Adapter 1: NAT
   - Adapter 2: Host-only Adapter
3. Attach Kali ISO

### 5.4 Install Kali Linux
1. Start the VM
2. Select **Graphical Install**
3. Choose language, location, keyboard
4. Set hostname: `kali-attacker`
5. Set username: `kali`
6. Set password
7. Partition: use entire disk
8. Install GRUB bootloader
9. Reboot

### 5.5 Configure Static IP
```bash
sudo nano /etc/network/interfaces
```
Add:
```
auto eth1
iface eth1 inet static
  address 192.168.56.102
  netmask 255.255.255.0
```
Restart networking:
```bash
sudo systemctl restart networking
```

### 5.6 Update Kali and install tools
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y hydra nmap wireshark metasploit-framework
```

---

## Step 6 — Verify Lab Connectivity

Test all VMs can communicate:

**From Kali:**
```bash
ping 192.168.56.101    # Should reach Ubuntu/Splunk
ping 192.168.56.103    # Should reach Windows 10
```

**From Ubuntu:**
```bash
ping 192.168.56.102    # Should reach Kali
ping 192.168.56.103    # Should reach Windows 10
```

---

## Lab Verification Checklist

| Task | Status |
|---|---|
| VirtualBox installed | Done |
| Host-only network configured (192.168.56.0/24) | Done |
| Ubuntu VM created with 4GB RAM / 50GB disk | Done |
| Ubuntu static IP set to 192.168.56.101 | Done |
| Windows 10 VM created with 2GB RAM / 50GB disk | Done |
| Windows 10 static IP set to 192.168.56.103 | Done |
| RDP enabled on Windows 10 | Done |
| Kali Linux VM created with 2GB RAM / 30GB disk | Done |
| Kali static IP set to 192.168.56.102 | Done |
| All VMs can ping each other | Done |

---

**Author:** Aigbokhaode Hope Imomoh — SOC Analyst
**LinkedIn:** https://www.linkedin.com/in/aigbokhaode-hope-imomoh-962717393
**GitHub:** https://github.com/aigbokhaodehope7-create
