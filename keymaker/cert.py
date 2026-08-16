"""Certificate generation and management via openssl."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def gen_cert(
    subject: str,
    days: int,
    key_bits: int,
    out_pfx: Path,
    pfx_pass: str = "",
    digest: str = "sha256",
) -> None:
    """Generate a self-signed code-signing certificate and export as PKCS#12 (.pfx).

    subject  — full DN string, e.g. 'CN=Cisco Systems,O=Cisco,C=US'
    days     — validity period
    key_bits — RSA key size (2048 / 3072 / 4096)
    out_pfx  — output .pfx path
    pfx_pass — password protecting the .pfx (empty = no password)
    digest   — hash algorithm (sha256 / sha384 / sha512)
    """
    with tempfile.TemporaryDirectory() as td:
        key = os.path.join(td, "key.pem")
        csr = os.path.join(td, "csr.pem")
        crt = os.path.join(td, "cert.pem")
        ext = os.path.join(td, "ext.cnf")

        # key
        _run(["openssl", "genrsa", "-out", key, str(key_bits)])

        # CSR
        _run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                key,
                "-out",
                csr,
                "-subj",
                f"/{subject.replace(',', '/')}" if "," in subject else f"/{subject}",
            ]
        )

        # Extension file — marks the cert as a code-signing cert
        Path(ext).write_text(
            "[v3_codesign]\n"
            "basicConstraints = CA:FALSE\n"
            "keyUsage = critical, digitalSignature\n"
            "extendedKeyUsage = critical, codeSigning\n"
            "subjectKeyIdentifier = hash\n"
        )

        # Self-signed cert
        _run(
            [
                "openssl",
                "x509",
                "-req",
                "-days",
                str(days),
                "-in",
                csr,
                "-signkey",
                key,
                "-out",
                crt,
                f"-{digest}",
                "-extensions",
                "v3_codesign",
                "-extfile",
                ext,
            ]
        )

        # Export PKCS#12
        pfx_cmd = [
            "openssl",
            "pkcs12",
            "-export",
            "-out",
            str(out_pfx),
            "-inkey",
            key,
            "-in",
            crt,
            "-passout",
            f"pass:{pfx_pass}",
        ]
        _run(pfx_cmd)


def import_pfx(src: Path, dst: Path, pfx_pass: str = "") -> None:
    """Copy (validate) an existing .pfx into the keystore directory."""
    # Validate by attempting to parse it
    _run(
        ["openssl", "pkcs12", "-in", str(src), "-noout", "-passin", f"pass:{pfx_pass}"]
    )
    import shutil

    shutil.copy2(src, dst)


def list_certs(store: Path) -> list[dict]:
    """Enumerate .pfx files in a store directory and extract Subject / notAfter."""
    certs = []
    for pfx in sorted(store.glob("*.pfx")):
        info = _cert_info(pfx)
        if info:
            certs.append({"file": pfx.name, **info})
    return certs


def clone_cert(
    domain: str,
    out_pfx: Path,
    pfx_pass: str = "",
    key_bits: int = 2048,
    digest: str = "sha256",
) -> dict:
    """Clone a domain's TLS cert metadata and generate a self-signed lookalike.

    Connects to domain:443 via openssl s_client, extracts CN/O/C/serial/validity,
    then calls gen_cert() with those fields.  Returns the parsed metadata dict.
    """
    import re

    # grab the cert PEM from the live domain
    r = subprocess.run(
        [
            "openssl",
            "s_client",
            "-connect",
            f"{domain}:443",
            "-servername",
            domain,
            "-showcerts",
        ],
        input="",
        capture_output=True,
        text=True,
        timeout=10,
    )
    pem_blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", r.stdout, re.DOTALL
    )
    if not pem_blocks:
        raise RuntimeError(f"could not retrieve certificate from {domain}")
    leaf_pem = pem_blocks[0]  # first = leaf cert

    # parse fields
    r2 = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates", "-serial"],
        input=leaf_pem,
        capture_output=True,
        text=True,
    )
    meta: dict = {}
    for line in r2.stdout.splitlines():
        k, _, v = line.partition("=")
        meta[k.strip()] = v.strip()

    # extract CN / O / C from subject line like "subject=CN=..., O=..., C=..."
    subj_line = next((v for k, v in meta.items() if "subject" in k.lower()), "")
    cn = re.search(r"CN\s*=\s*([^,\n]+)", subj_line)
    org = re.search(r"O\s*=\s*([^,\n]+)", subj_line)
    country = re.search(r"\bC\s*=\s*([A-Z]{2})", subj_line)

    cn_val = cn.group(1).strip() if cn else domain
    org_val = org.group(1).strip() if org else cn_val
    country_val = country.group(1).strip() if country else "US"

    # parse validity dates → days remaining (use notAfter - today for validity window)
    not_before = next(
        (v for k, v in meta.items() if "notBefore" in k or "before" in k.lower()), ""
    )
    not_after = next(
        (v for k, v in meta.items() if "notAfter" in k or "after" in k.lower()), ""
    )

    # compute days from today until notAfter
    import datetime

    try:
        exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days = max(30, (exp - datetime.datetime.utcnow()).days)
    except ValueError:
        days = 730

    dn = f"CN={cn_val},O={org_val},C={country_val}"
    gen_cert(
        subject=dn,
        days=days,
        key_bits=key_bits,
        out_pfx=out_pfx,
        pfx_pass=pfx_pass,
        digest=digest,
    )

    return {
        "domain": domain,
        "subject": dn,
        "not_before": not_before,
        "not_after": not_after,
        "days": days,
    }


def _cert_info(pfx: Path, pfx_pass: str = "") -> dict | None:
    try:
        # extract cert PEM from PFX
        r = _run(
            [
                "openssl",
                "pkcs12",
                "-in",
                str(pfx),
                "-nokeys",
                "-clcerts",
                "-passin",
                f"pass:{pfx_pass}",
            ]
        )
        # get subject + dates
        r2 = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-enddate"],
            input=r.stdout,
            capture_output=True,
            text=True,
        )
        subject, enddate = "", ""
        for line in r2.stdout.splitlines():
            if line.startswith("subject"):
                subject = line.split("=", 1)[-1].strip()
            elif line.startswith("notAfter"):
                enddate = line.split("=", 1)[-1].strip()
        return {"subject": subject, "expires": enddate}
    except Exception:
        return None
