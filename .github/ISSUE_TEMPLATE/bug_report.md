---
name: Bug report
about: A collector module, parser, or analyzer behaving incorrectly
title: "[bug] "
labels: bug
---

**What happened**
A clear description of the bug.

**Component**
- [ ] Collector module (which: ______)
- [ ] Raw parser (EVTX / prefetch / shimcache / amcache / MFT / USN / SRUM)
- [ ] Memory analysis (Volatility3 hand-off)
- [ ] Analyzer / MRI scoring / report
- [ ] Builder / packaging

**Environment**
- Target OS (collector): e.g. Windows 11 23H2 / Server 2022
- Analyst OS (analyzer):
- Version / commit:
- EDR/AV present (e.g. Defender, CrowdStrike):

**Repro steps**
1.
2.

**Expected vs actual**

**Logs / evidence**
Relevant lines from `collector.log` or the analyzer import output. Do NOT attach
real evidence containing sensitive host data — redact or use a synthetic sample.
