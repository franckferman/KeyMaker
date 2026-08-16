"""~/.keymaker/ cert store management."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from keymaker import cert

DEFAULT_ROOT = Path.home() / ".keymaker"
DEFAULT_CERTS = DEFAULT_ROOT / "certs"
INDEX_FILE = DEFAULT_ROOT / "index.json"


def init(root: Path = DEFAULT_ROOT) -> None:
    """Create store directory layout."""
    (root / "certs").mkdir(parents=True, exist_ok=True)


def _load_index(root: Path = DEFAULT_ROOT) -> dict:
    idx = root / "index.json"
    if idx.exists():
        try:
            return json.loads(idx.read_text())
        except Exception:
            pass
    return {}


def _save_index(data: dict, root: Path = DEFAULT_ROOT) -> None:
    idx = root / "index.json"
    idx.write_text(json.dumps(data, indent=2))


def add(
    pfx: Path, alias: str | None = None, pfx_pass: str = "", root: Path = DEFAULT_ROOT
) -> str:
    """Import a .pfx into the store and record it in index.json.

    Returns the alias used.
    """
    init(root)
    alias = alias or pfx.stem[:32]
    dst = root / "certs" / f"{alias}.pfx"
    if pfx != dst:
        shutil.copy2(pfx, dst)
    info = cert._cert_info(dst, pfx_pass) or {}
    idx = _load_index(root)
    idx[alias] = {
        "file": str(dst),
        "subject": info.get("subject", ""),
        "expires": info.get("expires", ""),
        "pass": pfx_pass,
    }
    _save_index(idx, root)
    return alias


def remove(alias: str, root: Path = DEFAULT_ROOT) -> bool:
    idx = _load_index(root)
    entry = idx.pop(alias, None)
    if not entry:
        return False
    pfx = Path(entry["file"])
    if pfx.exists():
        pfx.unlink()
    _save_index(idx, root)
    return True


def get(alias: str, root: Path = DEFAULT_ROOT) -> dict | None:
    return _load_index(root).get(alias)


def list_all(root: Path = DEFAULT_ROOT) -> list[dict]:
    idx = _load_index(root)
    return [{"alias": k, **v} for k, v in idx.items()]


def newest(root: Path = DEFAULT_ROOT) -> tuple[Path, str] | tuple[None, None]:
    """Return (pfx_path, pfx_pass) for the most recently modified cert."""
    certs_dir = root / "certs"
    if not certs_dir.exists():
        return None, None
    pfxs = sorted(
        certs_dir.glob("*.pfx"), key=lambda f: f.stat().st_mtime, reverse=True
    )
    if not pfxs:
        return None, None
    idx = _load_index(root)
    alias = pfxs[0].stem
    entry = idx.get(alias, {})
    return pfxs[0], entry.get("pass", "")
