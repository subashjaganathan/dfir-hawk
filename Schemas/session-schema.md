# .hawk Session Format — v1.0

A `.hawk` file is a ZIP container. Layout:

```
CASE-2026-001_HOSTNAME_20260602T120000Z.hawk
├── manifest.json                  ← session manifest (REQUIRED, see below)
├── artifacts\
│   ├── processes.json             ← one JSON file per artifact type
│   ├── network_tcp.json
│   ├── services.json
│   ├── registry_runkeys.json
│   ├── ... (one per module)
├── raw\
│   ├── evtx\Security.evtx         ← raw EVTX exports (all channels)
│   ├── registry\SYSTEM, SOFTWARE, NTUSER_<user>.DAT, Amcache.hve
│   ├── prefetch\*.pf
│   ├── srum\SRUDB.dat
│   ├── mft\$MFT, $UsnJrnl_J.bin
│   └── ps_transcripts\...
├── logs\collector.log             ← execution log
└── hashes.json                    ← SHA256 of every file in the container
```

## manifest.json

```json
{
  "schemaVersion": "1.0",
  "tool": { "name": "HawkCollector", "version": "2.0.0" },
  "case": {
    "caseNumber": "CASE-2026-001",
    "investigator": "name",
    "collectionStartUtc": "2026-06-02T12:00:00Z",
    "collectionEndUtc": "2026-06-02T12:14:33Z"
  },
  "host": {
    "hostname": "WS-FINANCE-07",
    "domain": "CORP",
    "os": { "caption": "...", "version": "10.0.26100", "build": 26100 },
    "role": "workstation | server | domain-controller | unknown",
    "timezone": "UTC+05:30",
    "ntpStatus": { "synchronized": true, "skewSeconds": 0.4 },
    "arch": "x64"
  },
  "preset": "standard | comprehensive | ioc-search",
  "modules": [
    {
      "name": "processes",
      "version": "2.0.0",
      "status": "success | partial | failed | skipped",
      "startedUtc": "...", "endedUtc": "...",
      "artifactFile": "artifacts/processes.json",
      "recordCount": 214,
      "errors": []
    }
  ],
  "rawArtifacts": [
    { "path": "raw/evtx/Security.evtx", "source": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
      "method": "vss | direct | rawcopy", "sha256": "..." }
  ]
}
```

## Artifact file envelope (every artifacts/*.json)

```json
{
  "schemaVersion": "1.0",
  "artifactType": "processes",
  "host": "WS-FINANCE-07",
  "collectedAtUtc": "2026-06-02T12:01:11Z",
  "records": [ ... ]
}
```

### Rules

1. **Records are raw observations.** No `IsSuspicious`, no `Severity`, no
   `RiskScore` fields anywhere in collector output. Those are analyzer columns.
2. **Timestamps**: ISO-8601 UTC with `Z` suffix, or literal `null`. Never a
   substituted/collection-time fallback.
3. **No truncation** of command lines, script blocks, or paths.
4. **schemaVersion** is checked by importer: same major = importable.
5. Every record that references a binary includes, when obtainable:
   `path`, `sha256`, `md5` (for NSRL), `signatureStatus`, `signer`.
   MD5 is required for whitelist matching — NSRL is keyed on MD5/SHA1.

## Key record shapes (analyzer contract)

### processes.json records
pid, ppid, name, path, commandLine, user, sessionId, startTimeUtc,
sha256, md5, signatureStatus(Valid|Invalid|NotSigned|Unknown), signer,
parentName, parentPath

### network_tcp.json records
protocol, localAddress, localPort, remoteAddress, remotePort, state,
pid, processName, processPath, creationTimeUtc

(remaining record shapes follow the existing module outputs, normalized to
camelCase with the envelope above — see Collector/Modules/CONTRACT.md)
