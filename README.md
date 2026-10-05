<div align="center">

# installtime-audit

**Audit Python packaging files for install-time side effects that run during `pip install`. Complements Bandit.**

[![PyPI](https://img.shields.io/pypi/v/installtime-audit?color=blue)](https://pypi.org/project/installtime-audit/)
[![Python](https://img.shields.io/pypi/pyversions/installtime-audit)](https://pypi.org/project/installtime-audit/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Downloads](https://static.pepy.tech/badge/installtime-audit/month)](https://pepy.tech/project/installtime-audit)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

</div>

---

Audit Python packaging files for **install-time side effects** — code that runs
during `pip install` and that malicious packages abuse to phone home, steal
credentials, or establish persistence. It's the supply-chain gap Bandit doesn't
specifically target.

Code at module scope in `setup.py` (and `build.py`, `hatch_build.py`, …), or
inside a build hook like `setup()` / `install.run()`, executes on install.
`installtime-audit` statically flags dangerous operations reachable at that
point — **without importing or running any of the target code.**

## Highlights

- Detects network, exec, credential theft, persistence and dependency-confusion patterns
- Purely static — never imports or runs the target code
- Only flags code reachable at install time, to keep noise low
- CWE-tagged findings, JSON output and CI-friendly exit codes

## Install

```bash
pip install installtime-audit
```

## What it flags

| Rule | CWE | Kind | Pattern |
| --- | --- | --- | --- |
| `INSTALL-NET` | 829 | warning | network fetch/connect during install |
| `INSTALL-EXEC` | 78 | vuln | `subprocess` / `os.system` during install |
| `INSTALL-DYNAMIC-EXEC` | 94 | vuln | `exec()` / `eval()` during install |
| `INSTALL-OBFUSCATED-EXEC` | 506 | vuln | `exec()` on a base64/marshal-decoded payload |
| `INSTALL-NET-EXEC` | 494 | vuln | **network + execution both reachable** (download-and-run) |
| `INSTALL-CREDS-ENV` | 522 | warning | reads a sensitive env var (`PYPI_TOKEN`, `AWS_*`, …) |
| `INSTALL-CREDS-FILE` | 522 | vuln | opens `~/.aws/credentials`, `~/.pypirc`, `~/.ssh/id_rsa`, … |
| `INSTALL-PERSISTENCE` | 506 | vuln | writes to autostart / cron / shell-rc paths |
| `DEPCONF-EXTRA-INDEX` | 829 | warning | `--extra-index-url` (dependency confusion) |
| `DEPCONF-TRUSTED-HOST` | 295 | warning | `--trusted-host` disables TLS verification |
| `DEPCONF-DEP-LINKS` | 829 | warning | `dependency_links` fetches from arbitrary URLs |
| `DEPCONF-DIRECT-URL` | 829 | warning | `@ https://...` direct-URL dependency in pyproject |

Helper functions that the build system never calls are **not** flagged, to keep
noise low — only module scope and known hooks count as reachable.

## Library usage

```python
from installtime_audit import scan_source, scan_path

for f in scan_source(open("setup.py").read(), filename="setup.py"):
    print(f)   # setup.py:12: [vuln] INSTALL-NET-EXEC (494) ...

# Or scan a whole unpacked package
findings = scan_path("./unpacked_package/")
```

## CLI

```bash
installtime-audit ./unpacked_package/
installtime-audit setup.py requirements.txt --json
```

Exit code is non-zero when a `vuln`-kind finding exists (tune with `--fail-on
any|vuln|never`), so it drops into CI easily.

## Caveats

This is a heuristic linter for triage, not proof of maliciousness. Legitimate
packages sometimes compile extensions or fetch data at build time; review each
finding in context.

## Development

```bash
git clone https://github.com/rahulreddykarne/installtime-audit.git
cd installtime-audit
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m build
```

Bug reports and pull requests are welcome on the [issue tracker](https://github.com/rahulreddykarne/installtime-audit/issues).

## Related projects

Part of a small toolkit for Python supply-chain security research:

| Project | What it does |
| --- | --- |
| [pypi-bulk-download](https://github.com/rahulreddykarne/pypi-bulk-download) | Bulk-download top PyPI packages in parallel with safe unpacking. |
| [tarslip-guard](https://github.com/rahulreddykarne/tarslip-guard) | Detect unsafe extractall() calls and safely extract tar/zip archives. |
| [pypi-version-bisect](https://github.com/rahulreddykarne/pypi-version-bisect) | Find a vulnerability's affected version range in O(log n) checks. |
| [pypi-blast-radius](https://github.com/rahulreddykarne/pypi-blast-radius) | Estimate the downstream impact of a PyPI package version. |
| [osv-dedupe](https://github.com/rahulreddykarne/osv-dedupe) | Score security findings against published OSV/NVD advisories. |
| [cvss-estimator](https://github.com/rahulreddykarne/cvss-estimator) | CVSS v3.1 calculator and evidence-driven vector estimator. |

## License

Released under the [MIT License](LICENSE).
