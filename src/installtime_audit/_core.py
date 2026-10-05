"""Detect install-time side effects in Python packaging files.

Code at module scope in ``setup.py`` (and friends), or inside a build-system
hook such as ``setup()`` / ``install.run()``, executes during ``pip install``.
This module flags dangerous operations reachable at that point: network access,
process execution, dynamic ``exec``/``eval``, obfuscated payloads, credential
access, filesystem persistence, and dependency-confusion index settings.

Detection is purely static (via :mod:`ast` and text scanning); no target code is
imported or executed.
"""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from . import _markers as M

_DIRECT_URL_RE = re.compile(r"@\s*https?://", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    """A single flagged install-time operation."""

    filename: str
    line: int
    rule: str
    cwe: str
    kind: str  # "vuln" or "warning"
    message: str

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "line": self.line,
            "rule": self.rule,
            "cwe": self.cwe,
            "kind": self.kind,
            "message": self.message,
        }

    def __str__(self) -> str:
        return f"{self.filename}:{self.line}: [{self.kind}] {self.rule} ({self.cwe}) {self.message}"


class _SupplyChainVisitor(ast.NodeVisitor):
    """Flag dangerous calls reachable during ``pip install``.

    Reachable = module scope, or inside a known build hook. Helper functions
    that are never called by the build system are not flagged.
    """

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.findings: list[Finding] = []
        self._imports: dict[str, str] = {}
        self._func_stack: list[str] = []
        self._net_lines: list[int] = []
        self._exec_lines: list[int] = []

    # -- scope tracking ----------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            self._imports[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self._imports[local] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._func_stack.append(node.name)
        self.generic_visit(node)
        self._func_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def _reachable(self) -> bool:
        if not self._func_stack:
            return True
        return self._func_stack[-1] in M.SETUP_HOOK_NAMES

    # -- helpers -----------------------------------------------------------
    def _resolve_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self._imports.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self._resolve_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""

    def _literal_string(self, node: Optional[ast.AST]) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                    return None
                parts.append(value.value)
            return "".join(parts)
        return None

    @staticmethod
    def _norm(value: str) -> str:
        return value.replace("\\", "/").lower()

    def _path_matches(self, value: str, markers) -> bool:
        norm = self._norm(value)
        return any(marker in norm for marker in markers)

    def _add(self, node: ast.AST, rule: str, cwe: str, kind: str, message: str) -> None:
        self.findings.append(
            Finding(self.filename, getattr(node, "lineno", 0), rule, cwe, kind, message)
        )

    # -- the check ---------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        if self._reachable():
            self._inspect_call(node)
        self.generic_visit(node)

    def _inspect_call(self, node: ast.Call) -> None:
        name = self._resolve_name(node.func)

        if name in M.HTTP_FETCH_CALLS or name in M.LOW_LEVEL_NET_CALLS:
            self._net_lines.append(node.lineno)
            self._add(
                node, "INSTALL-NET", "829", "warning",
                f"network access `{name}(...)` reachable during install",
            )

        if name in M.EXEC_CALLS:
            self._exec_lines.append(node.lineno)
            self._add(
                node, "INSTALL-EXEC", "78", "vuln",
                f"process execution `{name}(...)` reachable during install",
            )

        # exec()/eval() builtins
        if isinstance(node.func, ast.Name) and node.func.id in {"exec", "eval"}:
            self._exec_lines.append(node.lineno)
            arg = node.args[0] if node.args else None
            obfuscated = isinstance(arg, ast.Call) and self._resolve_name(arg.func) in M.OBFUSCATION_CALLS
            if obfuscated:
                self._add(
                    node, "INSTALL-OBFUSCATED-EXEC", "506", "vuln",
                    f"`{node.func.id}()` on a decoded/obfuscated payload during install",
                )
            else:
                self._add(
                    node, "INSTALL-DYNAMIC-EXEC", "94", "vuln",
                    f"dynamic `{node.func.id}()` reachable during install",
                )

        # credential file / env access
        if name == "os.getenv" or name == "os.environ.get":
            env = self._literal_string(node.args[0]) if node.args else None
            if env and env.upper() in M.SENSITIVE_ENV_NAMES:
                self._add(
                    node, "INSTALL-CREDS-ENV", "522", "warning",
                    f"reads sensitive environment variable `{env}` during install",
                )
        if name == "open" and node.args:
            target = self._literal_string(node.args[0])
            if target and self._path_matches(target, M.CREDENTIAL_PATH_MARKERS):
                self._add(
                    node, "INSTALL-CREDS-FILE", "522", "vuln",
                    f"opens credential file `{target}` during install",
                )
            if target and self._path_matches(target, M.PERSISTENCE_PATH_MARKERS):
                mode = self._literal_string(node.args[1]) if len(node.args) > 1 else None
                if mode and any(ch in mode for ch in ("w", "a", "x", "+")):
                    self._add(
                        node, "INSTALL-PERSISTENCE", "506", "vuln",
                        f"writes to persistence path `{target}` during install",
                    )

    def finalize(self) -> None:
        if self._net_lines and self._exec_lines:
            line = min(self._net_lines + self._exec_lines)
            self.findings.append(
                Finding(
                    self.filename, line, "INSTALL-NET-EXEC", "494", "vuln",
                    "both network access and code execution are reachable during "
                    "install — classic malicious-package download-and-run pattern",
                )
            )


def scan_source(code: str, filename: str = "setup.py") -> list[Finding]:
    """Return install-time findings for *code*. Raises SyntaxError if unparseable."""
    tree = ast.parse(code, filename=filename)
    visitor = _SupplyChainVisitor(filename)
    visitor.visit(tree)
    visitor.finalize()
    return visitor.findings


def scan_config_text(text: str, filename: str) -> list[Finding]:
    """Flag dependency-confusion settings in a config/requirements text file."""
    findings: list[Finding] = []
    base = os.path.basename(filename).lower()
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        lower = line.lower()
        if "--extra-index-url" in lower:
            findings.append(Finding(
                filename, i, "DEPCONF-EXTRA-INDEX", "829", "warning",
                "`--extra-index-url` can pull dependencies from an unexpected index "
                "(dependency confusion); verify the host is trusted",
            ))
        if "--trusted-host" in lower:
            findings.append(Finding(
                filename, i, "DEPCONF-TRUSTED-HOST", "295", "warning",
                "`--trusted-host` disables TLS verification for an index host",
            ))
        if "dependency_links" in lower:
            findings.append(Finding(
                filename, i, "DEPCONF-DEP-LINKS", "829", "warning",
                "`dependency_links` fetches dependencies from arbitrary URLs",
            ))
        if base == "pyproject.toml" and _DIRECT_URL_RE.search(line):
            findings.append(Finding(
                filename, i, "DEPCONF-DIRECT-URL", "829", "warning",
                "direct URL dependency reference (`@ https://...`); confirm the source",
            ))
    return findings


def scan_file(path: Union[str, Path]) -> list[Finding]:
    """Scan a single file with the appropriate checker based on its name."""
    p = Path(path)
    name = p.name.lower()
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings: list[Finding] = []
    if name in M.SETUP_FILENAMES or name.endswith(".py"):
        try:
            findings.extend(scan_source(text, filename=str(p)))
        except SyntaxError:
            pass
    if name in M.CONFIG_FILENAMES or name.startswith("requirements") or name == "pip.conf":
        findings.extend(scan_config_text(text, filename=str(p)))
    return findings


def scan_path(path: Union[str, Path]) -> list[Finding]:
    """Scan a file, or recursively scan the packaging-relevant files in a dir."""
    p = Path(path)
    if p.is_file():
        return scan_file(p)
    findings: list[Finding] = []
    for file in sorted(p.rglob("*")):
        if not file.is_file():
            continue
        name = file.name.lower()
        relevant = (
            name in M.SETUP_FILENAMES
            or name in M.CONFIG_FILENAMES
            or name.startswith("requirements")
        )
        if relevant:
            findings.extend(scan_file(file))
    return findings
