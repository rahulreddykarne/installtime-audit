"""Command-line interface for installtime-audit."""

from __future__ import annotations

import argparse
import json
import sys

from ._core import scan_path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="installtime-audit",
        description="Flag install-time side effects in Python packaging files.",
    )
    parser.add_argument("paths", nargs="+", help="files or project directories to scan")
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    parser.add_argument(
        "--fail-on",
        choices=["any", "vuln", "never"],
        default="vuln",
        help="exit non-zero when findings of this kind exist (default: vuln)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    findings = []
    for path in args.paths:
        findings.extend(scan_path(path))

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        for finding in findings:
            print(finding)
        print(f"{len(findings)} finding(s)", file=sys.stderr)

    if args.fail_on == "never":
        return 0
    if args.fail_on == "any":
        return 1 if findings else 0
    return 1 if any(f.kind == "vuln" for f in findings) else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
