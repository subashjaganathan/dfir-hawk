# DFIR Hawk — Architecture

A modern, open-source Windows incident-response triage and analysis platform.
Original, clean-room implementation.

```
┌─────────────────────────────────────────────────────────────────────┐
│ ANALYST MACHINE                                                     │
│                                                                     │
│  Hawk Analyzer (hawk.exe — .NET 8, single file)                     │
│  ├── Collector Builder UI  → generates portable collector package   │
│  ├── Session Importer      → .hawk → SQLite (hawk.db)               │
│  ├── Parser Engine         → EVTX / Prefetch / Shimcache / Amcache  │
│  │                           / SRUM / MFT parsed at IMPORT time     │
│  ├── Whitelist Engine      → NSRL bloom filter + org baseline       │
│  ├── MRI Scoring Engine    → per-process risk 0–100                 │
│  ├── IOC Matcher           → Sigma / YARA / OpenIOC                 │
│  └── UI (WebView2 window)  → MRI worklist, timeline, pivoting,      │
│                              tagging, HTML report export            │
└─────────────────────────────────────────────────────────────────────┘
                              ▲
                              │  SessionName.hawk  (ZIP container)
                              │
┌─────────────────────────────────────────────────────────────────────┐
│ TARGET HOST (victim machine — USB / network share, no install)      │
│                                                                     │
│  Hawk Collector (pure PowerShell 5.1 — Win7 → Server 2025)          │
│  ├── RunCollector.bat      → elevation + execution policy bypass    │
│  ├── Collector.ps1         → orchestrator (from Run_IR_Collection)  │
│  ├── Modules\*.ps1         → collection-only modules (existing 60+) │
│  └── config.json           → which modules + parameters (preset)    │
└─────────────────────────────────────────────────────────────────────┘
```

## Design rules

1. **Collector collects. Analyzer analyzes.** No scoring, no detection logic,
   no HTML on the target host. This is what kills false positives: detection
   runs where the whitelist lives.
2. **Trust ladder before suspicion.** Order of evaluation per artifact:
   NSRL hash match → trusted Authenticode signer → org baseline match →
   expected path/args/user rules → THEN scoring of what remains.
3. **Raw acquisition, deferred parsing.** Collector grabs locked files raw
   (VSS): $MFT, registry hives, EVTX, Amcache.hve, SRUM. Parsing happens at
   import on the analyst machine.
4. **One session = one SQLite DB.** All analysis state (scores, tags, notes,
   IOC hits) lives in hawk.db next to the session. Reports are generated
   from the DB *after* triage, not before.
5. **Schema versioning everywhere.** Every JSON artifact carries
   schemaVersion; the importer refuses unknown majors.

## Capabilities

| Area              | Implementation                                          |
|-------------------|---------------------------------------------------------|
| Collector builder | Presets: Standard / Comprehensive / IOC-Search          |
| Session file      | `.hawk` (ZIP: manifest + JSON + raw artifacts)          |
| Risk scoring      | MRI engine (`Configuration/MRI/*.json`), 0–100 per item |
| Known-good        | NSRL RDS bloom filter + org baseline                    |
| Timeline          | Pivot windows + field filters                           |
| IOC matching      | Sigma + YARA + OpenIOC import                           |
| Analyst UI        | WebView2 desktop window                                 |
| Memory            | WinPmem acquisition + Volatility3 hand-off              |

## Legal

No third-party binaries, whitelist data, or configuration content is included.
All rule content is sourced from public documentation (Microsoft docs, NSRL,
SANS posters, MITRE ATT&CK) and original work.
