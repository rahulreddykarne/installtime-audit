"""installtime-audit: flag install-time side effects in Python packaging files.

Public API
----------
- :func:`scan_source` – audit setup.py-style source for install-time danger.
- :func:`scan_config_text` – flag dependency-confusion settings in config text.
- :func:`scan_file`, :func:`scan_path` – audit files or a whole project tree.
- :class:`Finding` – a single flagged operation.
"""

from __future__ import annotations

from ._core import Finding, scan_config_text, scan_file, scan_path, scan_source

__all__ = ["Finding", "scan_source", "scan_config_text", "scan_file", "scan_path"]
__version__ = "0.1.0"
