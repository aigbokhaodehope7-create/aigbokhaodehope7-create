# Phishing Email Analysis Guide
## Identifying and Investigating Malicious Emails

**Author:** Aigbokhaode Hope Imomoh — SOC Analyst
**Tools:** Email headers, VirusTotal, URLScan.io, Any.run
**Framework:** MITRE ATT&CK T1566 — Phishing

---

## What is Phishing Analysis?

Phishing email analysis is a critical SOC skill. When a user reports a suspicious email, the SOC analyst must:

1. Extract and analyse email headers
2. Identify spoofed sender addresses
3. Analyse malicious links and attachments
4. Extract IOCs (URLs, IPs, file hashes)
5. Determine if the attack was successful
6. Block IOCs and prevent further damage

---

## Step 1 — Collect the Email

**How to get the raw email:**
- Outlook: File > Save As > .eml format
- Gmail: Three dots menu > Download message
- Thunderbird: File > Save As > .eml

**Never click links or open attachments directly!** Always work in a sandboxed environment.

---

## Step 2 — Analyse Email Headers

### How to Read Email Headers

**In Outlook:**
File > Properties > Internet Headers

**In Gmail:**
Three dots > Show original

### Key Header Fields to Examine

| Header | What to Look For |
|---|---|
| **From:** | Display name vs actual email address — look for spoofing |
| **Reply-To:** | Different from From: address — major red flag |
| **Return-Path:** | Should match From: domain |
| **Received:** | Trace the email path — look for unexpected servers |
| **X-Originating-IP:** | Original sender IP address |
| **Message-ID:** | Should match From: domain |
| **DKIM-Signature:** | Email authentication — pass or fail |
| **SPF:** | Sender Policy Framework — pass or fail |
| **DMARC:** | Domain-based authentication — pass or fail |

### Red Flags in Headers

```
From: PayPal Security <security@paypal-secure-login.com>
     ^--- Display name looks legit but domain is fake!

Reply-To: hacker@gmail.com
     ^--- Replies go to attacker, not PayPal!

Received: from mail.suspicious-domain.ru
     ^--- Email came from Russia, not PayPal servers!

Authentication-Results: spf=fail dkim=fail dmarc=fail
     ^--- All authentication checks failed = spoofed email!
```

---

## Step 3 — Analyse Phishing Email Sample

### Sample Phishing Email Analysis

**Email Details:**
```
From: "Microsoft Security Team" <security@micros0ft-alert.com>
To: hope@company.com
Subject: URGENT: Your Microsoft Account Has Been Compromised
Date: Mon, 22 Jun 2026 08:15:00 +0000
Reply-To: support@hacker-domain.ru
```

**Header Analysis:**

| Check | Result | Verdict |
|---|---|---|
| From domain | micros0ft-alert.com (note: zero not O) | FAKE — typosquat |
| SPF | FAIL | SUSPICIOUS |
| DKIM | FAIL | SUSPICIOUS |
| DMARC | FAIL | SUSPICIOUS |
| Reply-To | hacker-domain.ru | MALICIOUS |
| Originating IP | 185.234.xxx.xxx (Russia) | SUSPICIOUS |
| Received from | mail.hacker-domain.ru | MALICIOUS |

**Verdict: PHISHING EMAIL CONFIRMED**

---

## Step 4 — Analyse Malicious Links

### Safe Link Analysis Tools

| Tool | URL | Purpose |
|---|---|---|
| URLScan.io | https://urlscan.io | Scan URLs safely |
| VirusTotal | https://virustotal.com | Check URL/file reputation |
| Any.run | https://any.run | Interactive malware sandbox |
| Joe Sandbox | https://joesandbox.com | Automated malware analysis |
| Hybrid Analysis | https://hybrid-analysis.com | Free malware sandbox |

### Extracting Links Safely

**Never click the link directly!** Instead:

1. View email source code
2. Find the href= value in the HTML
3. Copy the URL
4. Submit to URLScan.io and VirusTotal

### URLScan.io Analysis Steps

1. Go to https://urlscan.io
2. Paste the suspicious URL
3. Click **Scan**
4. Review:
   - Screenshot of the page (is it a fake login page?)
   - IP address and hosting location
   - Domain registration date (new domains are suspicious)
   - Technologies used
   - Requests made (does it load resources from C2 servers?)

---

## Step 5 — Analyse Malicious Attachments

### Safe Attachment Analysis

**Never open attachments on your main machine!**

Use sandbox environments:
1. **Any.run** — https://any.run (interactive sandbox)
2. **VirusTotal** — https://virustotal.com (multi-engine scan)
3. **Hybrid Analysis** — https://hybrid-analysis.com

### What to Look For in Attachments

**Office Documents (.docx, .xlsx, .pdf):**
- Macros enabled? (common malware delivery)
- External connections made?
- Files dropped to disk?
- Registry changes?

**Executables (.exe, .dll):**
- File hash (submit to VirusTotal)
- Strings analysis (look for IPs, URLs, registry keys)
- Behaviour in sandbox (what does it do?)

### Extract File Hash

**On Windows:**
```cmd
certutil -hashfile suspicious.exe SHA256
```

**On Linux/Kali:**
```bash
sha256sum suspicious.exe
md5sum suspicious.exe
```

Submit hash to VirusTotal to check if it is known malware.

---

## Step 6 — Phishing Incident Report

### Sample Report

```
PHISHING EMAIL INCIDENT REPORT

Report ID: PHI-2026-001
Date: June 22, 2026
Analyst: Aigbokhaode Hope Imomoh
Severity: HIGH

INCIDENT SUMMARY:
A phishing email impersonating Microsoft Security Team was
reported by a user. The email contained a malicious link
directing to a credential harvesting page.

EMAIL DETAILS:
- From: security@micros0ft-alert.com (SPOOFED)
- Subject: URGENT: Your Microsoft Account Has Been Compromised
- Received: June 22, 2026 08:15 UTC
- Target: hope@company.com

AUTHENTICATION RESULTS:
- SPF: FAIL
- DKIM: FAIL
- DMARC: FAIL

MALICIOUS INDICATORS:
- Typosquatted domain: micros0ft-alert.com
- Reply-To: hacker-domain.ru
- Originating IP: 185.234.xxx.xxx (Russia)
- Malicious URL: http://micros0ft-alert.com/login.php
  - URLScan result: Credential harvesting page
  - VirusTotal: 23/87 engines flagged as malicious

IMPACT ASSESSMENT:
- User reports clicking the link but not entering credentials
- No evidence of credential compromise at this time
- No malicious attachment opened

CONTAINMENT ACTIONS:
1. Blocked sender domain at email gateway
2. Blocked malicious URL at web proxy
3. Blocked originating IP at firewall
4. Alerted all users about the phishing campaign
5. Checked email logs for other recipients

INDICATORS OF COMPROMISE (IOCs):
- Domain: micros0ft-alert.com
- IP: 185.234.xxx.xxx
- URL: http://micros0ft-alert.com/login.php
- Reply-To: hacker-domain.ru

MITRE ATT&CK:
- T1566.001 — Phishing: Spearphishing Attachment
- T1566.002 — Phishing: Spearphishing Link
- T1598.003 — Phishing for Information: Spearphishing Link

RECOMMENDATIONS:
1. Enable MFA on all email accounts immediately
2. Deploy email security gateway (Proofpoint/Mimecast)
3. Configure DMARC policy to reject on company domain
4. Conduct phishing awareness training for all staff
5. Implement URL rewriting to scan all links before delivery
```

---

## Step 7 — IOC Extraction Checklist

When analysing a phishing email, always extract:

- [ ] Sender email address (full)
- [ ] Sender domain
- [ ] Reply-To address
- [ ] Originating IP address
- [ ] All URLs in email body
- [ ] All attachment file names
- [ ] All attachment file hashes (MD5, SHA256)
- [ ] C2 domains contacted by malware
- [ ] C2 IP addresses

---

## MITRE ATT&CK — Phishing Techniques

| Technique | ID | Description |
|---|---|---|
| Spearphishing Attachment | T1566.001 | Malicious file in email |
| Spearphishing Link | T1566.002 | Malicious URL in email |
| Spearphishing via Service | T1566.003 | Phishing via social media/chat |
| Phishing for Information | T1598 | Credential harvesting pages |
| Obtain Capabilities: Malware | T1588.001 | Attacker using malware tools |

---

**Author:** Aigbokhaode Hope Imomoh — SOC Analyst
**LinkedIn:** https://www.linkedin.com/in/aigbokhaode-hope-imomoh-962717393
**GitHub:** https://github.com/aigbokhaodehope7-create
