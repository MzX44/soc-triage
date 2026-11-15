#!/usr/bin/env python3
"""
config.py  --  load the enabled enrichment connectors from config.yaml.

If no config file is found, falls back to sensible defaults (VirusTotal +
AbuseIPDB), each enabled only when its API key is present in the environment.
API keys are NEVER written in the YAML -- the YAML names an environment variable
(`api_key_env`) and the key is read from there at load time.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from . import connectors as C

DEFAULT_CONFIG_NAMES = ("config.yaml", "config.yml")

# Used when no config.yaml exists. Keeps zero-config behaviour working.
_DEFAULTS: list[dict[str, Any]] = [
    {"type": "virustotal", "api_key_env": "VIRUSTOTAL_API_KEY"},
    {"type": "abuseipdb", "api_key_env": "ABUSEIPDB_API_KEY"},
    {"type": "urlhaus", "api_key_env": "URLHAUS_AUTH_KEY"},  # free abuse.ch Auth-Key
]


def _instantiate(entry: dict[str, Any]) -> C.Connector:
    ctype = entry.get("type")
    if not ctype:
        raise ValueError(f"connector entry missing 'type': {entry}")
    api_key = os.getenv(entry["api_key_env"]) if entry.get("api_key_env") else None
    opts: dict[str, Any] = {"api_key": api_key}
    if ctype == "generic_rest":
        opts.update(
            display_name=entry.get("name", "GenericFeed"),
            url=entry.get("url", ""),
            supports=entry.get("supports", []),
            auth_header=entry.get("auth_header"),
            malicious_field=entry.get("malicious_field", ""),
            malicious_strong_at=int(entry.get("malicious_strong_at", 3)),
        )
    return C.build(ctype, **opts)


def _find_config(explicit: str | None) -> Path | None:
    if explicit:
        p = Path(explicit)
        return p if p.is_file() else None
    for name in DEFAULT_CONFIG_NAMES:
        p = Path.cwd() / name
        if p.is_file():
            return p
    return None


def load_connectors(config_path: str | None = None) -> list[C.Connector]:
    """Return instantiated connectors. Reads config.yaml if present, else defaults.

    A connector that needs a key but has none is dropped (with no error) so the
    tool runs with whatever credentials are actually available.
    """
    path = _find_config(config_path)
    entries: list[dict[str, Any]] = _DEFAULTS
    if path is not None:
        try:
            import yaml  # optional dependency; only needed for a custom config
        except ImportError as e:
            raise RuntimeError(
                "config.yaml found but PyYAML is not installed. "
                "Run: pip install pyyaml") from e
        doc = yaml.safe_load(path.read_text()) or {}
        entries = doc.get("connectors", _DEFAULTS)

    built: list[C.Connector] = []
    for entry in entries:
        conn = _instantiate(entry)
        # Drop a key-auth connector that has no key, so it is silently skipped.
        needs_key = bool(entry.get("api_key_env"))
        if needs_key and not conn.api_key:
            continue
        built.append(conn)
    return built
