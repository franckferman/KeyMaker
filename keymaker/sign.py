"""Binary signing via osslsigncode (PE/DLL) and pure-Python PKCS#7 (PS1)."""

from __future__ import annotations

import base64
import shutil
import subprocess
from pathlib import Path

# Timestamp servers — rotated per signing to avoid clustering
TIMESTAMP_SERVERS = [
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com",
    "http://timestamp.comodoca.com",
    "http://timestamp.apple.com/ts01",
]


def _osslsigncode() -> str:
    p = shutil.which("osslsigncode") or shutil.which(
        str(Path.home() / ".local/bin/osslsigncode")
    )
    if not p:
        raise RuntimeError("osslsigncode not found — run: make install-tools")
    return p


def sign_pe(
    target: Path,
    pfx: Path,
    pfx_pass: str = "",
    digest: str = "sha256",
    timestamp_srv: str | None = None,
    no_timestamp: bool = False,
    description: str = "",
    url: str = "",
    out: Path | None = None,
) -> Path:
    """Sign a PE binary (.exe / .dll / .sys) with osslsigncode.

    target      — input PE path
    pfx         — PKCS#12 cert + key
    pfx_pass    — PFX password (empty = none)
    digest      — sha256 / sha384 / sha512
    timestamp_srv — RFC-3161 TSA URL (None = auto-pick from pool)
    no_timestamp  — skip timestamping (faster, but sig dies with cert)
    description — optional program description (appears in Properties > Digital Signatures)
    url         — optional publisher URL
    out         — output path (default: overwrite target in-place via temp file)
    """
    binary = _osslsigncode()
    real_out = out or target

    # sign to a temp file alongside the target
    tmp = target.with_suffix(".signed.tmp")
    cmd = [
        binary,
        "sign",
        "-pkcs12",
        str(pfx),
        "-h",
        digest,
        "-in",
        str(target),
        "-out",
        str(tmp),
    ]
    if pfx_pass:
        cmd += ["-pass", pfx_pass]
    if description:
        cmd += ["-n", description]
    if url:
        cmd += ["-i", url]
    if not no_timestamp:
        srv = timestamp_srv or _pick_ts()
        cmd += ["-t", srv]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"osslsigncode failed: {r.stderr.strip()}")
        tmp.replace(real_out)
        return real_out
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def verify_pe(target: Path) -> dict:
    """Verify an Authenticode signature on a PE.

    Returns signed=True if a signature block is embedded (regardless of
    chain trust — self-signed certs fail osslsigncode's chain verify but
    are still fully embedded and visible in Windows signature dialogs).
    """
    binary = _osslsigncode()
    r = subprocess.run(
        [binary, "verify", str(target)],
        capture_output=True,
        text=True,
    )
    output = (r.stdout + r.stderr).strip()
    # "Signature Index:" is present whenever a sig block exists, even for
    # self-signed certs that fail chain verification (returncode != 0).
    signed = (
        r.returncode == 0
        or "Signature verification: ok" in output
        or "Signature Index:" in output
    )
    return {"signed": signed, "output": output}


def _pick_ts() -> str:
    """Rotate through timestamp servers for each signing operation."""
    import time

    idx = int(time.time()) % len(TIMESTAMP_SERVERS)
    return TIMESTAMP_SERVERS[idx]


def sign_ps1(
    target: Path,
    pfx: Path,
    pfx_pass: str = "",
) -> Path:
    """Append an Authenticode-compatible signature block to a .ps1 script.

    Implements the PowerShell Authenticode format (PKCS#7 CMS SignedData,
    SHA-256, DetachedSignature) using the cryptography library — no Windows
    tooling required.  The signature block appended at the end of the file
    is identical to what Set-AuthenticodeSignature produces.

    PowerShell verifies the signature when ExecutionPolicy is AllSigned or
    RemoteSigned; the signing cert must be trusted on the target host.

    target   — .ps1 path (modified in-place)
    pfx      — PKCS#12 bundle (cert + private key)
    pfx_pass — PFX password (empty = none)
    Returns: target path
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs7 as _pkcs7
    from cryptography.hazmat.primitives.serialization import pkcs12

    # Read script, strip any previous signature block
    content = target.read_text(encoding="utf-8", errors="replace")
    _begin = "# SIG # Begin signature block"
    if _begin in content:
        content = content[: content.index(_begin)].rstrip()

    # PowerShell hashes the script encoded as UTF-16LE (BOM-less)
    payload = content.encode("utf-16-le")

    # Load PFX
    pw = pfx_pass.encode() if pfx_pass else None
    private_key, certificate, _chain = pkcs12.load_key_and_certificates(
        pfx.read_bytes(), pw
    )

    # Build PKCS#7 CMS SignedData (detached — hash over payload, not embedded)
    builder = (
        _pkcs7.PKCS7SignatureBuilder()
        .set_data(payload)
        .add_signer(certificate, private_key, hashes.SHA256())
    )
    sig_der = builder.sign(
        serialization.Encoding.DER,
        [_pkcs7.PKCS7Options.DetachedSignature, _pkcs7.PKCS7Options.NoCerts],
    )

    # Format as PowerShell signature block (64-char base64 lines, each prefixed "# ")
    b64 = base64.b64encode(sig_der).decode()
    lines = ["# " + b64[i : i + 64] for i in range(0, len(b64), 64)]
    block = "\n".join(["", _begin, *lines, "# SIG # End signature block", ""])

    target.write_text(content + block, encoding="utf-8")
    return target
