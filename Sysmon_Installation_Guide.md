# Sysmon Installation and Configuration Guide
## Host-Based Telemetry for SOC Analysts

**Author:** Aigbokhaode Hope Imomoh — SOC Analyst
**Tool:** Sysmon v15.20
**Target:** Windows 10 (192.168.56.103)

---

## What is Sysmon?

Sysmon (System Monitor) is a Windows system service that logs detailed system activity to the Windows Event Log. It provides far more detail than standard Windows logging, including:

- Full process creation with command line
- Network connections with process name
- File creation and modification
- Registry changes
- DNS queries
- Driver and DLL loading

---

## Step 1 — Download Sysmon

1. Go to: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
2. Download **Sysmon** (Sysmon.zip)
3. Extract to `C:\Tools\Sysmon\`

---

## Step 2 — Download Sysmon Configuration

Use the SwiftOnSecurity Sysmon config (industry standard):

1. Go to: https://github.com/SwiftOnSecurity/sysmon-config
2. Download `sysmonconfig-export.xml`
3. Save to `C:\Tools\Sysmon\sysmonconfig.xml`

---

## Step 3 — Install Sysmon

Open **Command Prompt as Administrator**:

```cmd
cd C:\Tools\Sysmon\
sysmon64.exe -accepteula -i sysmonconfig.xml
```

Expected output:
```
System Monitor v15.20 - System activity monitor
Copyright (C) 2014-2024 Mark Russinovich and Thomas Garnier
Sysinternals - www.sysinternals.com

Loading configuration file with schema version 4.82
Sysmon schema version: 4.82
Configuration file validated.
Sysmon64 installed.
SysmonDrv installed.
Starting SysmonDrv.
SysmonDrv started.
Starting Sysmon64.
Sysmon64 started.
```

---

## Step 4 — Verify Installation

Check Sysmon is running:
```cmd
sc query sysmon64
```

Expected output:
```
SERVICE_NAME: sysmon64
TYPE               : 1  KERNEL_DRIVER
STATE              : 4  RUNNING
```

Check events are being generated:
1. Open **Event Viewer**
2. Navigate to: `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`
3. You should see events being logged

---

## Step 5 — Key Sysmon Event IDs to Monitor

| Event ID | Name | Description |
|---|---|---|
| 1 | ProcessCreate | New process created — includes full command line |
| 3 | NetworkConnect | Network connection made by a process |
| 7 | ImageLoad | DLL loaded by a process |
| 8 | CreateRemoteThread | Thread created in another process |
| 10 | ProcessAccess | Process accessing another process memory |
| 11 | FileCreate | File created or overwritten |
| 12 | RegistryEvent | Registry key/value created or deleted |
| 13 | RegistryEvent | Registry value set |
| 22 | DNSEvent | DNS query made by a process |

---

## Step 6 — Update Sysmon Config

To update the configuration without reinstalling:
```cmd
sysmon64.exe -c sysmonconfig.xml
```

To uninstall Sysmon:
```cmd
sysmon64.exe -u
```

---

## Step 7 — Verify Events in Splunk

After configuring Universal Forwarder (see Lab Setup guide), verify Sysmon events appear in Splunk:

```spl
index=sysmon earliest=-5m
| stats count by EventCode
| sort - count
```

Expected results:
- EventCode 1 (Process Create) — most common
- EventCode 3 (Network Connect) — frequent
- EventCode 11 (File Create) — frequent
- EventCode 22 (DNS Query) — frequent

---

## Sysmon Incident Report — Lab Findings

### Events Captured in Home Lab

| Event Type | Count | Key Finding |
|---|---|---|
| Process Creation (EventCode 1) | 1,847 | Hydra.exe process identified on attacker |
| Network Connection (EventCode 3) | 2,103 | RDP connections from 192.168.56.102 |
| DNS Query (EventCode 22) | 423 | Normal DNS resolution activity |
| File Creation (EventCode 11) | 312 | Normal file system activity |
| Registry Events (EventCode 13) | 198 | Normal registry activity |
| **Total Sysmon Events** | **5,900+** | Successfully ingested into Splunk |

### Key Detection — Hydra Process

Sysmon EventCode 1 captured the Hydra execution:
```
Image: C:\Users\kali\hydra.exe
CommandLine: hydra -l Hope -P rockyou.txt rdp://192.168.56.103
ParentImage: C:\Windows\System32\cmd.exe
User: kali\kali
```

---

**Author:** Aigbokhaode Hope Imomoh — SOC Analyst
**LinkedIn:** https://www.linkedin.com/in/aigbokhaode-hope-imomoh-962717393
**GitHub:** https://github.com/aigbokhaodehope7-create
