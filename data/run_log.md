# Atomic Red Team / Benign Activity Run Log

## Malicious half

| # | UTC Time | Host | Action | Technique | Test # / Command | Expected Sysmon Events | Alert Observed? | Notes |
|---|---|---|---|---|---|---|---|---|
| 1 | 2026-09-17T13:16:08-05:00 | det-lab-ws | Malicious (TP) | Scheduled task persistence (T1053.005) | `Invoke-AtomicTest T1053.005 -TestNumbers 1` | Event 1 (schtasks.exe) | Yes | **92032** (suspicious cmd shell). Banked. |
| 2 | 2026-09-17T13:28:25-05:00 | det-lab-ws | Malicious (TP) | Registry run key (T1547.001) | `Invoke-AtomicTest T1547.001 -TestNumbers 1` | Event 13 (\CurrentVersion\Run) | Yes | **92302** (+92041 Base64). Banked. Matched pair w/ B2. |
| 3 | 2026-09-18T14:21:37-05:00 | det-lab-ws | Malicious (TP) | Encoded PowerShell (T1059.001) | manual: `powershell -EncodedCommand <b64>` | Event 1 (powershell -enc) | Yes | **92057**. Manual (Atomic #1 was Mimikatz). Banked. |
| 4 | 2026-09-18T14:41:40-05:00 | det-lab-ws | Malicious (miss) | WMI exec (T1047) | `Invoke-AtomicTest T1047 -TestNumbers 7` | Event 1 (wmic.exe) | No | wmic absent on Win11; DISM prereq incomplete; did not execute. |
| 4.2 | 2026-10-02T13:31:16-05:00 | det-lab-ws | Malicious (miss) | WMI exec via Invoke-CimMethod (T1047) | `Invoke-CimMethod Win32_Process Create {calc.exe}` | Event 1 (WmiPrvSE parent) | No | Executed (RetVal 0, PID 8832); **no alert ≥3**. Coverage gap. Candidate rule 100501. RTP on. |
| 5 | 2026-10-02T13:43:05-05:00 | det-lab-ws | Malicious (TP) | SAM hive dump (T1003.002) | `reg save HKLM\SAM` + `reg save HKLM\SYSTEM` | Event 1 (reg.exe save SAM) | Yes | **92026** @18:43:08. LSASS/comsvcs route blocked by Defender (2147786203) + PPL (RunAsPPL 0x2); swapped to SAM. RTP off. Hives deleted. Banked. |
| 6 | 2026-10-02T13:50:18-05:00 | det-lab-ws | Malicious (TP) | Local Account Discovery (T1087.001) | `net user` ; `net localgroup administrators` | Event 1 (net.exe) | Yes | **92033** @18:50:21 (+92031 net1). RTP on. Pin label to 18:50:21. Matched pair w/ B9. Banked. |
| 7 | 2026-10-02T13:56:48-05:00 | det-lab-ws | Malicious (TP) | Clear Event Logs (T1070.001) | `wevtutil cl Security` | Event 1; Security 1102 | Yes | **63103** @18:56:34 (anchored on 1102 effect). RTP on. Matched pair w/ B10. Banked. |
| 8 | 2026-10-02T13:59:48-05:00 | det-lab-ws | Malicious (TP) | UAC Bypass fodhelper (T1548.002) | ms-settings hijack → `Start-Process fodhelper.exe` | Event 13 + Event 1 | Yes | **92305** @18:59:15 (+92306). Bypass succeeded (calc high-integrity) **then** Defender killed chain + PS session. RTP on. Hijack cleaned in new session. Banked. |
| 9 | 2026-10-02T14:13:51-05:00 | det-lab-ws | Malicious (miss) | Ingress Tool Transfer certutil (T1105) | `certutil -urlcache -split -f <url> ...` | Event 1/22/3/11 | No | Blocked Defender (2147726914) RTP on; executed RTP off (1078 B downloaded); **no alert ≥3**. Gap — Defender caught it, SIEM didn't. Candidate rule 100502. File deleted. |
| 10 | 2026-10-02T14:22:02-05:00 | det-lab-ws → DC | Malicious (TP) | Lateral Movement — remote schtasks (T1053.005 remote) | `schtasks /create /s WIN-IU1D5B3TEM3 ... /ru SYSTEM` | DC remote NTLM logon; Event 4698 | Yes | **92657** @19:25:48 (remote NTLM logon, possible PtH). Detection at **auth layer**, not task reg. **Alert under agent `det-lab-dc` (ID 014), NOT WIN-IU1D5B3TEM3.** Task deleted. Banked. |

## Benign-but-noisy half (RTP on throughout)

| # | UTC Time | Host | Action | Technique | Command | Expected Sysmon Events | Alert Observed? | Notes |
|---|---|---|---|---|---|---|---|---|
| B1 | 2026-10-02T14:52:15-05:00 | det-lab-ws | Benign (clean neg) | — (null) | `schtasks /create /tn LabBackup /sc daily` | Event 1 | No | Mirrors run 1. Ruleset correctly silent on benign admin task. No golden-set record. |
| B2 | 2026-10-02T14:52:32-05:00 | det-lab-ws | Benign (FP) | — (null) | `reg add ...\CurrentVersion\Run /v LabUpdater` | Event 13 | Yes | **92302 + 92041** @19:52:32. **IDENTICAL alert to malicious run 2.** Context-only distinction. **GOLDEN SET FP.** Matched pair w/ run 2. |
| B3 | 2026-10-02T14:52-05:00 | det-lab-ws | Benign (clean neg) | — (null) | `Get-Service` ; `Get-EventLog -LogName System` | Event 1 | No | Mirrors run 3. Silent. No record. |
| B4 | 2026-10-02T14:54:42-05:00 | det-lab-ws | Benign (clean neg) | — (null) | `Get-CimInstance Win32_OperatingSystem / Win32_Service` | — | No | Read-only WMI, no WmiPrvSE spawn. Mirrors run 4. No record. |
| B5 | 2026-10-02T14:54:42-05:00 | det-lab-ws | Benign (clean neg) | — (null) | `Start-MpScan -ScanType QuickScan` | Event 10 (signed src) | No | Benign MsMpEng→lsass access below threshold — correct. Mirrors run 5 by absence (same target, opposite verdict AND opposite alerting). No record. |
| B6 | 2026-10-02T15:00:27-05:00 | det-lab-ws → DC | Benign (clean neg) | — (null) | `Get-CimInstance -ComputerName WIN-IU1D5B3TEM3` | — | No | Logon churn + 67028 only. Read-only remote auth stays below 92657 privileged-auth threshold. Mirrors run 10. No record. |
| B7 | 2026-10-02T15:01:57-05:00 | det-lab-ws | Benign (FP) | — (null) | `winget install 7zip.7zip` (7-Zip 26.03) | — | Yes | **60610 / 60612 / 61104** @20:02. Install cluster (installer began + app installed + service startup change). Representative: **60612**. **GOLDEN SET FP.** |
| B8 | 2026-10-02T14:54:42-05:00 | det-lab-ws | Benign (clean neg) | — (null) | `gpupdate /force` | Event 1 | No | Logon churn only. Clean. No record. |
| B9 | 2026-10-02T15:04:17Z (UTC) | det-lab-ws | Benign (FP) | — (null) | `net user` (incidental setup activity, earlier today) | — | Yes | **92031** @15:04:17 UTC. **IDENTICAL alert to malicious run 6.** Context-only distinction. **GOLDEN SET FP.** Matched pair w/ run 6. (Incidental — not a staged run; timestamp is UTC alert time = 10:04 local.) |
| B10 | 2026-10-02T14:58-05:00 | det-lab-ws | Benign (clean neg) | — (null) | `wevtutil qe Security /c:5 /rd:true /f:text` | — | No | Read vs run 7's clear — ruleset correctly distinguishes. Sharpest mirror pair. No record. |

---

## Golden set composition — 11 labeled records

**True positives (8):**

| id | run | rule | technique | observed_utc |
|---|---|---|---|---|
| gs-001 | 1 | 92032 | T1053.005 | 2026-09-17T18:16:16Z |
| gs-002 | 2 | 92302 | T1547.001 | 2026-09-17T18:28:16Z |
| gs-003 | 3 | 92057 | T1059.001 | 2026-09-18T19:20:59Z |
| gs-004 | 5 | 92026 | T1003.002 | 2026-10-02T18:43:08Z |
| gs-005 | 6 | 92033 | T1087.001 | 2026-10-02T18:50:21Z |
| gs-006 | 7 | 63103 | T1070.001 | 2026-10-02T18:56:34Z |
| gs-007 | 8 | 92305 | T1548.002 | 2026-10-02T18:59:15Z |
| gs-008 | 10 | 92657 | T1053.005 | 2026-10-02T19:25:48Z |

**False positives (3):**

| id | run | rule | technique | observed_utc | pairs with |
|---|---|---|---|---|---|
| gs-009 | B2 | 92302 | null | 2026-10-02T19:52:32Z | gs-002 |
| gs-010 | B7 | 60612 | null | 2026-10-02T20:02:32Z | — |
| gs-011 | B9 | 92031 | null | 2026-10-02T15:04:17Z | gs-005 |

**Matched pairs (identical/near-identical alert, opposite label — the core eval cases):** gs-002 ↔ gs-009 (run-key 92302), gs-005 ↔ gs-011 (net user discovery).

**Documented misses (run-log only, not golden-set records):** run 4.2 WMI exec (gap → candidate rule 100501), run 9 certutil download (gap → candidate rule 100502).

**Clean negatives (correct silence, run-log only):** B1, B3, B4, B5, B6, B8, B10.

---

## Environment / policy notes

- **Execution policy:** `RemoteSigned` / `CurrentUser` (set this session; reverted snapshot defaulted to `Restricted`, which blocked the Atomic install). Not a security boundary.
- **Defender RTP:** on by default; toggled off per-run only for runs 5 (SAM) and 9 (certutil) where behavioral detection blocked execution, restored after each. Entire benign half ran RTP on.
- **Defender as a control (finding):** behaviorally blocked every credential-access / LOLBin-download attempt with RTP on (LSASS 2147786203, SAM 2147816575/2147726914); caught fodhelper post-execution.
- **DC name mismatch (affects Days 5–7):** DNS = `WIN-IU1D5B3TEM3.detlab.local` → 10.10.50.21 (resolve/RPC); Wazuh agent name = `det-lab-dc` (ID 014). Asset YAML + export filter must key on `det-lab-dc`. DECISION PENDING: DNS alias vs. accept dual names.
