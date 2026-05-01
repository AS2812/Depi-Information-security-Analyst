# 🛡️ Building & Operating a Mini Security Operations Center (SOC)

> **Project 1 — Final Presentation**  
> Alexandria University & EJUST University · Computer & Data Sciences

**Team:**  
- **Ahmed Shacker** *(Team Leader)*  
- Moaz Eid · Asem Soliman · Mohamed Ibrahim

---

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Why a SOC?](#why-a-soc)
- [Project Roadmap](#project-roadmap)
- [SOC Architecture](#soc-architecture)
- [Lab Environment](#lab-environment)
- [SOC Components](#soc-components)
- [Week 1 — SOC Setup & Log Ingestion](#week-1--soc-setup--log-ingestion)
- [Week 2 — SIEM Configuration & Use Case Development](#week-2--siem-configuration--use-case-development)
  - [Whitelisting Strategy](#whitelisting-strategy)
  - [Use Case 01 — SSH Brute Force](#use-case-01--ssh-brute-force)
  - [Use Case 02 — Outbound C2 Beacon](#use-case-02--outbound-c2-beacon)
  - [Use Case 03 — RDP Brute Force Success](#use-case-03--rdp-brute-force-success)
  - [Use Case 04 — Malware Process Chain](#use-case-04--malware-process-chain)
  - [Use Case 05 — Pass-the-Hash / NTLM](#use-case-05--pass-the-hash--ntlm)
  - [Use Case 06 — Ransomware Shadow Copy Deletion](#use-case-06--ransomware-shadow-copy-deletion)
  - [Use Case 07 — Ransomware Mass File Rename](#use-case-07--ransomware-mass-file-rename)
  - [Use Case 08 — Network Service Discovery / Port Scan](#use-case-08--network-service-discovery--port-scan)
  - [Use Case 09 — Initial Access Web Exploit Probe](#use-case-09--initial-access-web-exploit-probe)
- [Use Case Map](#use-case-map)
- [Week 3 — Alert Triage & Incident Management](#week-3--alert-triage--incident-management)
- [Week 4 — Reporting & Final Presentation](#week-4--reporting--final-presentation)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [KPI Dashboard](#kpi-dashboard)
- [Business Recommendations](#business-recommendations)
- [Lessons Learned](#lessons-learned)

---

## Project Overview

**Objective:** Simulate a full SOC workflow including log ingestion, threat detection, alert triage, MITRE ATT&CK mapping, KPI dashboards, and final reporting.

| Metric | Value |
|--------|-------|
| Duration | 4 weeks |
| Detection Rules | 9 |
| Rule Firings | 1,196 |
| MITRE Tactics Covered | 8 / 8 selected (100%) |
| Data Sources | 4 indexes (windows, linux, firewall, ids) |
| Attack Simulations | 9 live lab attacks |
| SIEM Platform | Splunk Cloud (`prd-p-29z6y`) |

---

## Why a SOC?

A Security Operations Centre converts raw machine data into early warning, accountability, and measurable risk reduction.

| Benefit | Detail |
|---------|--------|
| 🕐 Reduce dwell time | Industry average attacker dwell time is ~16 days. A live SOC slashes that to minutes. |
| 💰 Lower breach cost | IBM 2024 report: organisations with a SOC save ≈ $2.2M per breach vs those without. |
| 📋 Compliance evidence | Audit-ready logs satisfy ISO 27001, PCI-DSS, NIST 800-53 logging controls. |
| 🤝 Customer trust | Demonstrable monitoring is increasingly a vendor due-diligence requirement. |
| 🔒 Insider deterrence | Simply visible logging deters malicious insiders and reduces accidental misuse. |
| 📈 Continuous improvement | KPIs (MTTD, MTTR, false-positive rate) make security progress measurable. |

---

## Project Roadmap

```
WEEK 01 ── Setup & Ingestion
           Lab build, log sources wired into Splunk Cloud via SC4S + UF + Suricata

WEEK 02 ── SIEM & Use Cases
           CIM models accelerated, 9 detection rules deployed with whitelists

WEEK 03 ── Triage & IR
           Live attacks across all 9 use cases fired 1,196 rule events

WEEK 04 ── Reporting & RCA
           KPI dashboard, root-cause analysis, business recommendations
```

---

## SOC Architecture

```
LOG SOURCES                  COLLECTORS                SIEM PLATFORM
─────────────────            ──────────────────        ─────────────────────
pfSense Firewall  ──syslog──▶ SC4S Container  ──HEC──▶
  192.168.229.1               (TLS encrypted)           Splunk Cloud
                                                         prd-p-29z6y
Windows 11 (Ahmed)──UF──────▶                  ──────▶   ┌─ firewall index
  192.168.52.135                                          ├─ ids index
                                                          ├─ linux index
Ubuntu + Suricata ──UF──────▶ Universal        ──────▶   └─ windows index
  192.168.52.128               Forwarder
                               (TCP 9997 TLS)
                                                DETECTIONS: 9 rules · 1,196 firings · 8 MITRE tactics
```

**9 detection rules run on a 1-minute schedule in Splunk Cloud.**

---

## Lab Environment

Five virtual machines on VMware Workstation. Each VM plays a single role; pfSense provides network segmentation.

| VM | Role | IP Address |
|----|------|-----------|
| pfSense | Firewall + log generator | `192.168.229.1` / WAN `192.168.52.134` |
| Windows 11 (Ahmed) | Endpoint + attack source | `192.168.52.135` |
| Kali Linux | SC4S collector + attacker | `192.168.52.134` |
| Ubuntu + Suricata | UF host + IDS | `192.168.52.128` / `192.168.52.129` |
| Splunk Cloud | Indexer + SIEM | `prd-p-29z6y.splunkcloud.com` |

> **Network segmentation:** pfSense at `192.168.229.1` enforces Anti-Lockout, LAN-allow rules. All other traffic must explicitly pass — providing a clean choke-point for the SOC to monitor.

---

## SOC Components

| Component | Role | Business Value |
|-----------|------|----------------|
| **pfSense Firewall** | Source of truth for network events | Detects scanning, lateral movement, exfiltration patterns at the perimeter |
| **SC4S (Splunk Connect for Syslog)** | Normalises syslog → HEC | Single config swap for any syslog vendor. No re-engineering when firewall changes. |
| **Universal Forwarder** | File monitor for OS logs | Captures Linux `auth.log` + Windows EventLog with low overhead and store-and-forward reliability |
| **Suricata IDS** | Deep packet inspection | Catches what filterlog misses — malware C2, exploit signatures, anomalous user-agents |
| **Splunk Cloud** | Indexer + SIEM + scheduler | Centralises all data, runs detections every minute, generates the analyst alert queue |

---

## Week 1 — SOC Setup & Log Ingestion

### Steps Completed

1. **pfSense Firewall Logs** — filterlog flowing live to SC4S via syslog UDP/TCP 514  
2. **SC4S Collector** — Docker container healthy (`ghcr.io/splunk/splunk-connect-for-syslog/container3:latest`), ports 514 and 601 listening  
3. **HEC Token & Indexes** — 4 indexes provisioned in Splunk Cloud: `firewall`, `ids`, `linux`, `windows`  
4. **Universal Forwarder** — splunkd active on Ubuntu, connected to `inputs.prd-p-29z6y.splunkcloud.com:9997` over TLS  
5. **Index Health Validated** — all sources streaming live events  
6. **Custom Suricata Signatures** — 4 `MINISOC.*` rules authored for lab-specific patterns

### Index Health Summary

| Index | Events | Source |
|-------|--------|--------|
| `firewall` | 441 + 2,301 | pfSense filterlog via SC4S |
| `ids` | 22,448 | Suricata EVE JSON |
| `linux` | 111 + 2,301 | Ubuntu auth.log via UF |
| `windows` | 6,016 Security + 107 App | WinEventLog via UF |

### Custom Suricata Signatures

```
MINISOC SSH CONNECTION OBSERVED    — fires on SSH connections to lab hosts
MINISOC HTTP PORT 8080 CONNECTION  — fires on C2 beacon port pattern
MINISOC IDS HTTP USER-AGENT TEST   — fires on custom MiniSOC-C2-Test user-agent
MINISOC WEB PROBE DETECTED         — fires on suspicious HTTP path patterns
```

---

## Week 2 — SIEM Configuration & Use Case Development

### Whitelisting Strategy

Every detection rule uses a named lookup CSV. Activity matching an active whitelist entry is suppressed without editing the SPL rule.

Each whitelist entry contains: `src_ip`, `owner`, `reason`, `whitelist_active`, `expiry_date`

| Whitelist File | Suppresses |
|----------------|-----------|
| `minisoc_ssh_whitelist.csv` | Approved bastion hosts and CI runners |
| `minisoc_rdp_whitelist.csv` | Help-desk jump hosts and known admins |
| `minisoc_c2_whitelist.csv` | Windows Update, Splunk, vendor cloud APIs |
| `minisoc_process_chain_whitelist.csv` | Admin scripts and software deployment |
| `minisoc_ntlm_whitelist.csv` | Legacy NTLM systems where Kerberos is impossible |
| `minisoc_shadowcopy_whitelist.csv` | Scheduled backup software rotating VSS |
| `minisoc_ransomware_rename_whitelist.csv` | Batch-rename utilities and migration jobs |
| `minisoc_discovery_whitelist.csv` | Approved vulnerability scanners / SOC test IPs |
| `minisoc_webprobe_whitelist.csv` | Approved web scanners and QA tools |

---

### Use Case 01 — SSH Brute Force

**MITRE:** `T1110.001` — Brute Force: Password Guessing  
**Severity:** HIGH  
**Alert Name:** `SSH_Brute_Force_Detection`  
**Evidence Count:** 118

**Business Need:** Externally-exposed SSH is hit by automated guessing within minutes of going online. A single weak password becomes initial access for ransomware or data theft.

**Attack Simulation:**
```
Tool:   THC-Hydra v9.6
Target: 192.168.52.129 (Ubuntu SOC) port 22
List:   ssh_users.txt (root/admin/ubuntu/test) × bad_passwords.txt (10 passwords)
Threads: 4 parallel
Result: 40/40 pairs tried · 0 valid passwords (SSH key-only hardening confirmed)
Events: 241+ auth.log failed-auth entries generated
MTTD:   < 5 minutes
```

**SPL Rule Logic:**
1. Search 3 indexes for SSH-related keywords
2. `rex` extracts `username`, `src_ip`, `target_host`
3. Coalesce `src_ip2` fallback if regex fails
4. Filter for non-null `src_ip` only
5. Bucket time into 10-minute windows
6. `stats`: count failures + unique users per IP
7. Lookup whitelist to suppress known scanners
8. `where whitelist_active != 1`
9. Threshold: 5+ failures triggers alert
10. Case severity: ≥20 CRITICAL, ≥5 HIGH, else MED
11. MITRE `T1110.001` + `alert_type` field appended

**Detection Result:** 12 failed attempts · 1 unique user (`fakeuser`) · severity HIGH

**Recommendation:** Block source IP at pfSense for 24h. Force MFA on SSH. Disable password auth in favour of keys for service accounts.

---

### Use Case 02 — Outbound C2 Beacon

**MITRE:** `T1071.001` — Application Layer Protocol: Web Protocols  
**Severity:** HIGH  
**Alert Name:** `Outbound_C2_Beacon_Detection`  
**Evidence Count:** 720

**Business Need:** After initial compromise, malware beacons to attacker infrastructure. Regular small requests to suspicious ports — detectable by pattern.

**Attack Simulation:**
```
Method:  Python HTTP server on 192.168.52.134:8080
User-Agent: MiniSOC-C2-Test (custom header)
Beacons: 60+ requests from Windows host over 10 minutes
Evidence: pfSense filterlog + Suricata custom UA signature
```

**SPL Rule Logic:**
1. Search `index=firewall` filterlog only
2. `rex` extracts 13 fields from CSV format
3. Filter `action=pass` and `dst_port` in `[80, 443, 8080, 8443, 4444, 1337]`
4. Case `dst_scope`: internal CIDR / loopback / external
5. Case `port_risk`: 4444/8080 = suspicious_port; 80/443 = web_port
6. Bucket `_time span=10m` sliding window
7. Stats: connection_count + protocols + interfaces
8. Lookup whitelist → suppress approved update servers
9. Threshold: suspicious_port ≥ 5, web_port ≥ 30
10. Case severity: ≥50 CRITICAL, ≥threshold HIGH
11. MITRE `T1071.001` + alert_type emitted

**Detection Result:** 40 events · 20 connections / 10m bucket · severity HIGH

**Recommendation:** Force all egress through authenticated proxy. Block ports 4444, 1337, 8080 at pfSense unless whitelisted.

---

### Use Case 03 — RDP Brute Force Success

**MITRE:** `T1110.001` + `T1078` — Brute Force + Valid Accounts  
**Severity:** CRITICAL  
**Alert Name:** `RDP_Brute_Force_Success`  
**Evidence Count:** 56

**Business Need:** RDP exposed to a flat LAN is one of the top 3 ransomware entry points. Detecting the moment a brute force succeeds is critical.

**Attack Simulation:**
```
Method:  net use \\192.168.52.135\IPC$ /user:rdpuser <WrongPass1..5>
Events:  Event 4625 (failed logon) × 24 + Event 4624 (success) × 3
Total:   31 events · Logon Type 3 (network) · NTLM auth
```

**SPL Rule Logic:**
1. Search `index=windows` for EventCode 4624 OR 4625
2. `rex` extracts `failed_user` / `success_user` separately
3. Extract `Logon_Type` and `Source_Network_Address`
4. Case outcome: 4625 = failure, 4624 = success
5. Bucket `_time span=30m` sliding window
6. Stats: count failures + successes + first/last seen
7. `where failures >= 5 AND successes >= 1`
8. Case severity: failures ≥ 20 CRITICAL, ≥ 5 HIGH
9. MITRE `T1110.001` + `T1078` dual-tagged

**Detection Result:** 24 failures / 30m · 3 successful logons · severity CRITICAL

**Recommendation:** Immediately disable compromised account. Force password reset for ALL accounts. Move RDP behind VPN. Set account lockout threshold to 5 attempts.

---

### Use Case 04 — Malware Process Chain

**MITRE:** `T1059.001` + `T1059.003` — PowerShell + cmd  
**Severity:** CRITICAL  
**Alert Name:** `Malware_Process_Chain`  
**Evidence Count:** 30

**Business Need:** 95% of modern malware uses living-off-the-land binaries. Watching the parent → child process relationship catches what static AV misses.

**Attack Simulation:**
```
Chain:   cmd.exe → powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand
Payload: MiniSOC_ProcessChain_Test (safe base64 test string)
Events:  7 process-creation events (Windows Event 4688)
```

**SPL Rule Logic:**
1. Search `index=windows EventCode=4688`
2. Coalesce + lower process names + command_line
3. `where new_process` matches `powershell.exe` OR `pwsh.exe`
4. `where parent_process` matches `cmd` / `wscript` / `mshta` / Office apps
5. Case `suspicious_reason`: encoded or obfuscated PowerShell
6. Match: `-enc` / `-e` / `iex` / `DownloadString` / `FromBase64String`
7. Lookup whitelist → suppress approved admin scripts
8. Case severity: encoded_obfuscated CRITICAL, flags HIGH

**Detection Result:** 7 process spawns / 24h · `powershell.exe` new_process · `-EncodedCommand` flag · severity CRITICAL

**Recommendation:** Enable PowerShell Constrained Language Mode for non-admins. Deploy Sysmon for richer telemetry. Block Office → cmd/powershell at AppLocker.

---

### Use Case 05 — Pass-the-Hash / NTLM

**MITRE:** `T1550.002` + `T1078` — Use Alternate Authentication Material  
**Severity:** HIGH  
**Alert Name:** `Pass_The_Hash_Detection`  
**Evidence Count:** 334

**Business Need:** Once an attacker has an NTLM hash, they can authenticate to any Windows machine accepting NTLM — without knowing the password.

**Attack Simulation:**
```
Method:  net use \\192.168.52.135\IPC$ with rdpuser credentials
Events:  Windows Event 4624 · Logon_Type=3 (network) · AuthPackage=NTLM
Result:  2 NTLM logons captured in 30m bucket
```

**SPL Rule Logic:**
1. Search `index=windows source=WinEventLog:Security`
2. Filter `EventCode 4624` + `user=rdpuser`
3. `rex` extracts `auth_package` + `ntlm_package_name`
4. `where logon_type='3'` AND `auth_package` matches NTLM
5. Bucket `_time span=30m`
6. Stats: ntlm_logon_count + values(logon_type) + auth_packages
7. `where ntlm_logon_count >= 1` (any NTLM is suspect)
8. Case severity: ≥5 CRITICAL, ≥1 HIGH
9. MITRE `T1550.002` + `T1078` dual-tagged

**Detection Result:** 2 NTLM logons / 30m · 3 distinct logon types · severity HIGH

**Recommendation:** Disable NTLM where possible (force Kerberos). Enable Credential Guard on all Windows 10/11 endpoints. Deploy Protected Users group for privileged accounts.

---

### Use Case 06 — Ransomware Shadow Copy Deletion

**MITRE:** `T1490` — Inhibit System Recovery  
**Severity:** CRITICAL  
**Alert Name:** `Ransomware_ShadowCopy_Deletion`  
**Evidence Count:** 12

**Business Need:** Ransomware ALWAYS deletes Volume Shadow Copies before encrypting. Catching `vssadmin delete shadows` is the single highest-fidelity ransomware indicator that exists.

**Attack Simulation:**
```
Command: vssadmin.exe delete shadows /for=z: /all /quiet
Shell:   Admin cmd.exe
Events:  3 process-creation events (Windows Event 4688)
```

**SPL Rule Logic:**
1. Search `index=windows source=WinEventLog:Security`
2. Filter `EventCode=4688` (process creation)
3. `where new_process LIKE %vssadmin.exe%` OR cmd contains `vssadmin`
4. `where command_line` matches `delete` AND `shadow`
5. Case `deletion_scope`: /all = all_shadow_copies, /for = specific_volume
6. Lookup whitelist → suppress backup software maintenance windows
7. Case severity: all_shadow_copies CRITICAL, specific_volume HIGH
8. MITRE `T1490` (Inhibit System Recovery)

**Detection Result:** 3 shadow-delete attempts · `deletion_scope=/all` · severity CRITICAL

**Recommendation:** Restrict `vssadmin.exe` to SYSTEM via AppLocker. Deploy immutable backups (Veeam Hardened Repository, S3 Object Lock). Isolate host immediately on this alert.

---

### Use Case 07 — Ransomware Mass File Rename

**MITRE:** `T1486` — Data Encrypted for Impact  
**Severity:** CRITICAL  
**Alert Name:** `Ransomware_Mass_File_Rename`  
**Evidence Count:** 756

**Business Need:** During encryption, ransomware renames every file with a suspicious extension. Detecting the burst at 10–50 files catches encryption in progress.

**Attack Simulation:**
```
Script:  ransomware_rename_attack.ps1
Path:    C:\soc_test\ransomware_lab\
Action:  Created 50 files (file1.txt...file50.txt) → renamed to .encrypted
Time:    Under 2 minutes
Events:  100 file events generated
```

**SPL Rule Logic:**
1. Search `index=windows source=WinEventLog:Security`
2. Filter for `ransomware_lab` path OR `.encrypted/.locked/.crypt/.enc`
3. Case `extension`: classify the renamed file's new extension
4. Case `protected_path`: lab / documents / desktop / downloads
5. Bucket `_time span=10m`
6. Stats: `file_event_count` + `dc(unique_files)` + extensions used
7. Lookup whitelist → suppress file migration jobs
8. Threshold: `unique_files >= 10` OR `file_event_count >= 20`
9. Case severity: unique ≥ 50 CRITICAL, ≥ 10 HIGH
10. MITRE `T1486` (Data Encrypted for Impact)

**Detection Result:** 100 file events / 30m · 50 unique files renamed · `.encrypted` extension · severity CRITICAL

**Recommendation:** Auto-isolate host on first alert (NAC quarantine VLAN). Deploy honeypot canary files. Snapshot file shares hourly.

---

### Use Case 08 — Network Service Discovery / Port Scan

**MITRE:** `T1046` — Network Service Discovery  
**Severity:** HIGH  
**Alert Name:** `Network_Service_Discovery_Scan`  
**Evidence Count:** 637

**Business Need:** Before brute force or exploitation, attackers scan hosts to find open services. Detecting reconnaissance gives the SOC 15–30 minutes to block before escalation.

**Attack Simulation:**
```
Tool 1:  nmap from Kali → 192.168.52.135 and 192.168.52.129
Ports:   22, 80, 443, 445, 3389, 8080
Tool 2:  Test-NetConnection loops from Windows through pfSense
Total:   637 firewall/IDS evidence events
```

**SPL Rule Logic:**
1. Search `index=firewall` OR `index=ids`
2. Extract `dest_port` + `src_ip` + `action` from pfSense + Suricata
3. Stats: `dc(dest_port) as unique_ports`, `count as event_count`
4. Lookup whitelist → suppress approved vulnerability scanners
5. `where unique_ports >= 5` OR `event_count >= 10`
6. Bucket `_time span=5m` by src_ip
7. Severity: HIGH (≥5 unique ports)
8. MITRE `T1046` — Network Service Discovery

**Detection Result:** 637 events · 10+ unique ports scanned · severity HIGH — WORKING

**Recommendation:** Identify source, confirm if approved scanner, block at firewall if unauthorized, investigate next-stage activity.

---

### Use Case 09 — Initial Access Web Exploit Probe

**MITRE:** `T1190` — Exploit Public-Facing Application  
**Severity:** HIGH  
**Alert Name:** `Initial_Access_Web_Exploit_Probe`  
**Evidence Count:** 356

**Business Need:** Web probing is the most common first step before public app exploitation. Detecting requests to admin paths and config files catches attackers early.

**Attack Simulation:**
```
Method:  curl from Windows → Kali Python HTTP server
Paths:   /wp-login.php, /admin, /.env, /index.php?id=1, /phpmyadmin, /login
Server:  Kali python3 -m http.server 8080 (returned 404s)
Total:   356 firewall/IDS evidence events
```

**SPL Rule Logic:**
1. Search `index=firewall` OR `index=ids`
2. Extract `url` + `dest_port` + `src_ip` from Suricata HTTP / pfSense
3. Match URL against suspicious path list
4. Stats: `count as probe_count` by `src_ip`, `url_path`
5. Lookup whitelist → suppress approved QA scanners
6. `where probe_count >= 3` (multiple suspicious paths)
7. Severity: HIGH (3+ probes)
8. MITRE `T1190` — Exploit Public-Facing Application

**Detection Result:** 356 events · 6 suspicious paths probed · severity HIGH — WORKING

**Recommendation:** Review web server logs for probed paths. Block source IP at WAF/firewall. Patch any exposed services matching probed paths.

---

## Use Case Map

All 9 use cases confirmed **WORKING** in Splunk Cloud. Stored as `minisoc_usecase_map.csv` lookup driving alerts, dashboards, and analyst triage.

| # | Use Case | Alert Name | MITRE | Severity | Evidence Count | Business Impact |
|---|----------|-----------|-------|----------|---------------|-----------------|
| UC01 | SSH Brute Force | `SSH_Brute_Force_Detection` | T1110.001 | HIGH | 118 | Linux server compromise |
| UC02 | Outbound C2 Beacon | `Outbound_C2_Beacon_Detection` | T1071.001 | HIGH | 720 | Active malware C2 channel |
| UC03 | RDP Brute Force Success | `RDP_Brute_Force_Success` | T1110.001+T1078 | CRITICAL | 56 | Compromised Windows account |
| UC04 | Malware Process Chain | `Malware_Process_Chain` | T1059.001+T1059.003 | CRITICAL | 30 | Script-based malware execution |
| UC05 | NTLM Lateral Movement | `Pass_The_Hash_Detection` | T1550.002+T1078 | HIGH | 334 | Credential abuse / lateral movement |
| UC06 | Shadow Copy Deletion | `Ransomware_ShadowCopy_Deletion` | T1490 | CRITICAL | 12 | Recovery backups destroyed |
| UC07 | Mass File Rename | `Ransomware_Mass_File_Rename` | T1486 | CRITICAL | 756 | Files being encrypted |
| UC08 | Network Service Discovery | `Network_Service_Discovery_Scan` | T1046 | HIGH | 637 | Pre-attack reconnaissance |
| UC09 | Web Exploit Probe | `Initial_Access_Web_Exploit_Probe` | T1190 | HIGH | 356 | Public-facing app probing |

**Total rule firings: 1,196**

---

## Week 3 — Alert Triage & Incident Management

### 5-Step Triage Workflow

Every alert flows through this playbook so analyst handoffs stay consistent and repeatable.

```
1. DETECT      Alert fires from correlation rule with severity + MITRE tag
      ↓
2. VALIDATE    Confirm not a false positive — check whitelists, recent changes
      ↓
3. INVESTIGATE Pivot logs across indexes, gather IOCs (IP, user, file hash)
      ↓
4. CONTAIN     Block IP at pfSense, disable account, isolate host
      ↓
5. DOCUMENT    Triage sheet + RCA + lessons learned for next time
```

1,196 rule events across 9 use cases ran through this workflow — covering 8 MITRE techniques, 4 severity levels.

### Alert Breakdown

| Use Case | Firings | Severity |
|----------|---------|----------|
| Outbound C2 Beacon | 720 | HIGH |
| NTLM Lateral Movement | 334 | HIGH |
| Network Service Discovery | 637 | HIGH |
| Web Exploit Probe | 356 | HIGH |
| SSH Brute Force | 118 | HIGH |
| Malware Process Chain | 30 | HIGH |
| RDP Brute Force Success | 56 | CRITICAL |
| Shadow Copy Deletion | 12 | CRITICAL |
| Mass File Rename | 756 | CRITICAL |

---

## Week 4 — Reporting & Final Presentation

### KPI Dashboard

| KPI | Value |
|-----|-------|
| Mean Time to Detect (MTTD) | **< 5 minutes** (Hydra → alert: 4m 22s) |
| Total Rule Firings | **1,196** across 9 rules |
| Detection Rules | **9** (all MITRE-tagged) |
| Selected MITRE Tactic Coverage | **100%** (8 of 8 selected tactics) |
| Data Sources | **4** indexes |
| Whitelist CSVs | **9** (one per use case) |
| Evidence Window | 24 hours |
| False Positives After Whitelisting | ~2 / week |

### Saved Searches Inventory

All 9 rules enabled, scheduled (cron), owner `sc_admin`:

```
Network_Service_Discovery_Scan
Initial_Access_Web_Exploit_Probe
SSH_Brute_Force_Detection
RDP_Brute_Force_Success
Outbound_C2_Beacon_Detection
Malware_Process_Chain
Pass_The_Hash_Detection
Ransomware_ShadowCopy_Deletion
Ransomware_Mass_File_Rename
```

---

## MITRE ATT&CK Coverage

**8 of 8 selected tactics covered — 100% selected project kill-chain visibility.**

> Note: This is selected project coverage, not full MITRE Enterprise ATT&CK.

| Tactic | Technique | Status | Detection |
|--------|-----------|--------|-----------|
| Initial Access | T1190 | ✅ COVERED | Web Exploit Probe |
| Execution | T1059 | ✅ COVERED | Malware Process Chain |
| Credential Access | T1110 | ✅ COVERED | SSH + RDP Brute Force |
| Defense Evasion | T1550 | ✅ COVERED | Pass-the-Hash / NTLM Abuse |
| Discovery | T1046 | ✅ COVERED | Network Service Discovery Scan |
| Lateral Movement | T1021 | ✅ COVERED | SMB / Remote Logon / NTLM |
| Command & Control | T1071 | ✅ COVERED | Outbound C2 Beacon |
| Impact | T1486+T1490 | ✅ COVERED | Ransomware (Mass Rename + Shadow Copy) |

**Coverage: 8 / 8 selected tactics · 100%**

---

## Business Recommendations

| Priority | Action | ROI |
|----------|--------|-----|
| ⚡ Quick Win | **Move RDP behind VPN/MFA** | Eliminates 95% of credential-spray attacks. Prevents 1 ransomware incident ≈ $850K saved. |
| ⚡ Quick Win | **Block uncommon egress at firewall** | Block ports 4444/1337/8080 except whitelisted apps. Blocks 70% of off-the-shelf C2 frameworks. |
| 🔧 Medium | **Force Kerberos, disable NTLM** | Eliminates Pass-the-Hash attack class entirely. Closes the most common lateral-movement vector. |
| 🔧 Medium | **Deploy EDR + Sysmon** | Replaces noisy Event 4688 with rich process telemetry, network connections, file hashes. 10× detection fidelity. |
| 📅 Strategic | **Threat-intel feed integration** | Auto-correlate IOCs against MISP / OTX / commercial feeds. Catches campaign-level activity. |
| 📅 Strategic | **24/7 SOC analyst rotation** | Current single-analyst model has 16h/day coverage gap. Cuts MTTR from hours to minutes during off-hours. |

---

## Lessons Learned

> *"Building a SOC is plumbing, not magic."*

1. **Pipelines first, alerts second** — 60% of project effort went into making logs flow reliably. With a clean pipeline, every detection became a 30-min job. Without it, every detection was a 3-day job.

2. **CIM acceleration is non-negotiable** — Pre-acceleration, our 24h SSH brute-force search took 47 seconds. Post-acceleration: 1.2s. This is the difference between iterating on rules and giving up.

3. **Whitelists do 80% of FP reduction** — Our first SSH rule produced 12 FPs/week (Nessus scans, IT-OPS jump host). After adding 9 whitelists: 0 FPs/week, same TP rate. Lookup-based suppression beats SPL edits every time.

4. **MITRE labelling enables coverage analysis** — Tagging every rule with a tactic+technique made the gap analysis trivial. You can't fix what you can't measure.

5. **Custom IDS signatures catch what generic rules miss** — 4 lab-specific `MINISOC.*` Suricata signatures fired more reliably than the 30,000+ ET ruleset for our specific attack patterns. Tailor your IDS to your threat model.

6. **SC4S + pfSense routing required careful IP routing fixes** — Logs appeared only after fixing syslog destination IP and ensuring pfSense remote logging pointed to the correct SC4S container port.

7. **NTLM is trivially triggered** — Disabling NTLMv1 is non-negotiable in any real environment.

8. **Root cause analysis: most misses were routing/config gaps, not SPL errors** — Always verify data is flowing before debugging detection logic.

---

## Incident Reporting Framework (Module 8)

### Executive Summary Template (5Ws)

| W | Detail |
|---|--------|
| **WHO** | Attacker: Kali Linux `192.168.52.128` · Victims: Ubuntu `192.168.52.129`, Windows `192.168.52.135` |
| **WHAT** | 9 coordinated attack simulations: brute force, C2 beaconing, NTLM relay, ransomware staging, port scanning, web probing |
| **WHEN** | 2026-04-30 22:00 — 2026-05-01 10:22 UTC · MTTD < 5 minutes per alert type |
| **WHERE** | VMware lab LAN `192.168.229.0/24` + VMnet8 · Splunk Cloud: `prd-p-29z6y.splunkcloud.com` |
| **WHY** | Controlled academic simulation for Project 1 — SOC framework. No real data compromised. |

### Incident Timeline

```
2026-04-30 22:00  LAB START      VMs booted. All 4 Splunk indexes receiving live events.
2026-05-01 06:15  ATTACK PHASE 1 SSH Hydra (40 pairs), nmap port scan, web exploit probe from Kali.
2026-05-01 06:20  FIRST ALERT    SSH_Brute_Force_Detection fires. MTTD: < 5 min.
2026-05-01 09:42  ATTACK PHASE 2 RDP spray, C2 beacon curl loop, process chain, vssadmin shadow delete, file rename (50 files).
2026-05-01 10:22  ALL 9 WORKING  All rules confirmed firing. 1,196 alerts logged. Dashboard + PDF exported.
```

### RCA — Selected Incident: RDP Brute Force Success

**Root Cause:** Weak test account (`rdpuser`) credentials allowed successful network authentication (Event 4624) after repeated failures (Event 4625).

**Containment Steps:**
- Disable compromised account
- Reset password
- Kill all active sessions
- Block source IP at pfSense
- Enforce MFA on all remote access
- Restrict SMB/RDP to VPN-only

**Prevention:**
- Account lockout threshold ≤ 5 attempts
- Mandatory MFA for all remote access
- Disable unnecessary remote services
- Monitor 4625 → 4624 pattern continuously
- Apply principle of least privilege

---

## Project Team

| Name | Role |
|------|------|
| **Ahmed Shacker** | **Team Leader** |
| Moaz Eid | Team Member |
| Asem Soliman | Team Member |
| Mohamed Ibrahim | Team Member |

**Institution:** Alexandria University & EJUST University  
**Course:** Computer & Data Sciences — Project 1  

---

*Mini SOC Project — Building & Operating a Security Operations Center*
