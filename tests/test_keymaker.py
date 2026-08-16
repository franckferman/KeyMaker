"""KeyMaker test suite — no live network, no osslsigncode required for most tests."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from keymaker import vendors
from keymaker.cert import _cert_info, gen_cert, import_pfx, list_certs
from keymaker.cli import build_parser, main
from keymaker.sign import TIMESTAMP_SERVERS, _pick_ts, sign_ps1, verify_pe
from keymaker.steal import (
    _find_versioninfo,
    _sec_dir,
    check,
    graft,
    graft_sig,
    graft_with_meta,
    read_meta,
)
from keymaker.steal import remove as steal_remove
from keymaker.steal import (
    rip,
    rip_meta,
)
from keymaker.store import add, get, list_all, newest, remove
from keymaker.ui import err, heading, info, ok, table, warn

# ── steal ─────────────────────────────────────────────────────────────────────

_PE_HDR_OFF = 0x80  # e_lfanew: PE signature starts at file offset 128


def _make_minimal_pe(cert_off: int = 0, cert_sz: int = 0, magic: int = 0x20B) -> bytes:
    """Minimal PE64 (PE32+) for steal tests.

    Layout:
      0x00 - 0x7F : DOS stub (128 bytes), e_lfanew=0x80 at offset 0x3C
      0x80 - 0x83 : PE signature "PE\\0\\0"
      0x84 - 0x97 : COFF header (20 bytes)
      0x98+       : Optional header (240 bytes for PE32+)
      opt_start   = 0x80 + 4 + 20 = 0x98 = 152
      sec_entry   = opt_start + 144 = 296  (for PE32+)
    """
    import struct as _s

    dos = bytearray(_PE_HDR_OFF)
    dos[0:2] = b"MZ"
    _s.pack_into("<I", dos, 0x3C, _PE_HDR_OFF)

    coff = bytearray(20)
    _s.pack_into("<H", coff, 0, 0x8664)  # AMD64
    _s.pack_into("<H", coff, 16, 240)  # SizeOfOptionalHeader
    _s.pack_into("<H", coff, 18, 0x0022)

    opt = bytearray(240)
    _s.pack_into("<H", opt, 0, magic)
    sec_off = 144 if magic == 0x20B else 128
    _s.pack_into("<I", opt, sec_off, cert_off)
    _s.pack_into("<I", opt, sec_off + 4, cert_sz)

    return bytes(dos) + b"PE\x00\x00" + bytes(coff) + bytes(opt)


def _make_pe32_pe(cert_off: int = 0, cert_sz: int = 0) -> bytes:
    """Minimal PE32 (0x10B) — security dir entry at opt_start + 128."""
    import struct as _s

    dos = bytearray(_PE_HDR_OFF)
    dos[0:2] = b"MZ"
    _s.pack_into("<I", dos, 0x3C, _PE_HDR_OFF)
    coff = bytearray(20)
    _s.pack_into("<H", coff, 0, 0x014C)  # i386
    _s.pack_into("<H", coff, 16, 224)
    opt = bytearray(224)
    _s.pack_into("<H", opt, 0, 0x10B)
    _s.pack_into("<I", opt, 128, cert_off)
    _s.pack_into("<I", opt, 132, cert_sz)
    return bytes(dos) + b"PE\x00\x00" + bytes(coff) + bytes(opt)


class TestStealParsing:
    def test_sec_dir_unsigned_pe64(self):
        data = _make_minimal_pe()
        entry, off, sz = _sec_dir(data)
        assert off == 0
        assert sz == 0

    def test_sec_dir_signed_pe64(self):
        opt_start = _PE_HDR_OFF + 4 + 20  # 152
        expected_entry = opt_start + 144  # 296
        data = bytearray(_make_minimal_pe(cert_off=500, cert_sz=100))
        entry, off, sz = _sec_dir(data)
        assert entry == expected_entry
        assert off == 500
        assert sz == 100

    def test_sec_dir_pe32(self):
        opt_start = _PE_HDR_OFF + 4 + 20  # 152
        expected_entry = opt_start + 128  # 280
        data = bytearray(_make_pe32_pe(cert_off=300, cert_sz=50))
        entry, off, sz = _sec_dir(data)
        assert entry == expected_entry
        assert off == 300
        assert sz == 50

    def test_sec_dir_bad_magic(self):
        data = bytearray(_make_minimal_pe(magic=0xDEAD))
        with pytest.raises(ValueError, match="unsupported PE magic"):
            _sec_dir(data)

    def test_check_unsigned(self, tmp_path):
        pe = tmp_path / "u.exe"
        pe.write_bytes(_make_minimal_pe(cert_off=0, cert_sz=0))
        assert check(pe) is False

    def test_check_signed(self, tmp_path):
        pe = tmp_path / "s.exe"
        pe.write_bytes(_make_minimal_pe(cert_off=999, cert_sz=42))
        assert check(pe) is True


class TestStealOps:
    def setup_method(self):
        import tempfile

        self.tmp = Path(tempfile.mkdtemp())

    def teardown_method(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_signed_pe(self, name="signed.exe") -> Path:
        """PE with a fake cert blob appended at the end."""
        blob = b"\xde\xad\xbe\xef" * 16  # 64-byte fake PKCS#7
        # build unsigned PE then set cert dir to point at end-of-file
        p = self.tmp / name
        p.write_bytes(_make_minimal_pe(cert_off=0, cert_sz=0))
        # now graft the blob onto itself using the steal module logic
        import struct as _s

        base = bytearray(p.read_bytes())
        cert_off = len(base)
        opt_start = _PE_HDR_OFF + 4 + 20
        entry = opt_start + 144  # PE32+
        _s.pack_into("<I", base, entry, cert_off)
        _s.pack_into("<I", base, entry + 4, len(blob))
        p.write_bytes(bytes(base) + blob)
        return p

    def _make_unsigned_pe(self, name="unsigned.exe") -> Path:
        p = self.tmp / name
        p.write_bytes(_make_minimal_pe())
        return p

    def test_rip_extracts_blob(self):
        src = self._make_signed_pe()
        sig = rip(src)
        assert sig.exists()
        assert sig.read_bytes() == b"\xde\xad\xbe\xef" * 16

    def test_rip_custom_output(self):
        src = self._make_signed_pe()
        out = self.tmp / "out.sig"
        rip(src, out)
        assert out.exists()

    def test_rip_unsigned_raises(self):
        u = self._make_unsigned_pe()
        with pytest.raises(ValueError, match="not signed"):
            rip(u)

    def test_graft_produces_output(self):
        src = self._make_signed_pe("src.exe")
        tgt = self._make_unsigned_pe("tgt.exe")
        out = graft(src, tgt)
        assert out.exists()
        # cert table should now be non-zero in output
        assert check(out) is True

    def test_graft_blob_appended(self):
        src = self._make_signed_pe("src.exe")
        tgt = self._make_unsigned_pe("tgt.exe")
        out = graft(src, tgt)
        data = out.read_bytes()
        assert b"\xde\xad\xbe\xef" * 16 in data

    def test_graft_unsigned_source_raises(self):
        u1 = self._make_unsigned_pe("u1.exe")
        u2 = self._make_unsigned_pe("u2.exe")
        with pytest.raises(ValueError, match="not signed"):
            graft(u1, u2)

    def test_graft_sig_from_file(self):
        src = self._make_signed_pe("src.exe")
        tgt = self._make_unsigned_pe("tgt.exe")
        sig = rip(src)
        out = graft_sig(sig, tgt)
        assert check(out) is True

    def test_remove_zeros_cert_dir(self):
        src = self._make_signed_pe()
        out = steal_remove(src)
        assert out.exists()
        assert check(out) is False

    def test_remove_truncates_blob(self):
        src = self._make_signed_pe()
        original_size = src.stat().st_size
        out = steal_remove(src)
        assert out.stat().st_size < original_size

    def test_remove_unsigned_raises(self):
        u = self._make_unsigned_pe()
        with pytest.raises(ValueError, match="not signed"):
            steal_remove(u)

    def test_remove_custom_output(self):
        src = self._make_signed_pe()
        out = self.tmp / "clean.exe"
        steal_remove(src, out)
        assert out.exists()


class TestStealCLI:
    def test_steal_no_op_returns_0(self, capsys):
        rc = main(["steal"])
        assert rc == 0

    def test_steal_check_missing_file(self, capsys):
        rc = main(["steal", "check", "/nonexistent/file.exe"])
        assert rc == 0  # check prints per-file, doesn't abort

    def test_steal_rip_missing_file(self, capsys):
        rc = main(["steal", "rip", "/nonexistent/file.exe"])
        assert rc == 1

    def test_steal_remove_missing_file(self, capsys):
        rc = main(["steal", "remove", "/nonexistent/file.exe"])
        assert rc == 1


# ── steal — VS_VERSION_INFO (VersionInfo resource) ────────────────────────────


def _make_versioninfo_bytes(fields: dict) -> bytes:
    """Build a minimal VS_VERSION_INFO blob parseable by _extract_meta_strings."""
    import struct as _s

    def utf16(s: str) -> bytes:
        return s.encode("utf-16-le") + b"\x00\x00"

    def pad32(b: bytes) -> bytes:
        n = len(b) % 4
        return b + (b"\x00" * ((4 - n) % 4))

    def make_string_entry(key: str, val: str) -> bytes:
        k = utf16(key)
        v = utf16(val)
        hdr = _s.pack("<HHH", 0, len(val) + 1, 1)
        chunk = pad32(hdr + k) + pad32(v)
        buf = bytearray(chunk)
        _s.pack_into("<H", buf, 0, len(chunk))
        return bytes(buf)

    # VS_VERSION_INFO header: wLength(2) + wValueLength(2) + wType(2) + key(32) + pad(2) + FIXEDFILEINFO(52)
    marker = utf16("VS_VERSION_INFO")  # 32 bytes
    fixed = _s.pack("<I", 0xFEEF04BD) + b"\x00" * 48  # 52 bytes
    base = _s.pack("<HHH", 0, 52, 0) + marker + b"\x00\x00" + fixed

    entries = b"".join(make_string_entry(k, v) for k, v in fields.items())
    blob = base + entries
    buf = bytearray(blob)
    _s.pack_into("<H", buf, 0, len(blob))
    return bytes(buf)


def _make_pe_with_vi(vi_blob: bytes, signed: bool = False) -> bytes:
    """Minimal PE64 with VS_VERSION_INFO embedded in the file body."""
    import struct as _s

    fake_cert = b"\xca\xfe\xba\xbe" * 16 if signed else b""
    base_pe = _make_minimal_pe()  # 392 bytes (DOS+PE+COFF+OPT)
    body = base_pe + vi_blob
    if not signed:
        return body
    cert_off = len(body)
    cert_sz = len(fake_cert)
    result = bytearray(body + fake_cert)
    opt_start = _PE_HDR_OFF + 4 + 20  # 152
    entry = opt_start + 144  # 296 (PE32+)
    _s.pack_into("<I", result, entry, cert_off)
    _s.pack_into("<I", result, entry + 4, cert_sz)
    return bytes(result)


class TestStealVersionInfo:
    def setup_method(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.vi = _make_versioninfo_bytes(
            {
                "CompanyName": "Acme Corp",
                "ProductName": "AcmeTool",
                "FileVersion": "1.2.3.4",
            }
        )

    def teardown_method(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _pe(self, name: str, signed: bool = False) -> Path:
        p = self.tmp / name
        p.write_bytes(_make_pe_with_vi(self.vi, signed=signed))
        return p

    # _find_versioninfo
    def test_find_versioninfo_present(self):
        data = _make_pe_with_vi(self.vi)
        result = _find_versioninfo(data)
        assert result is not None
        offset, length = result
        assert length == len(self.vi)

    def test_find_versioninfo_absent(self):
        data = _make_minimal_pe()
        assert _find_versioninfo(data) is None

    # read_meta
    def test_read_meta_returns_fields(self):
        pe = self._pe("r.exe")
        fields = read_meta(pe)
        assert fields["CompanyName"] == "Acme Corp"
        assert fields["ProductName"] == "AcmeTool"
        assert fields["FileVersion"] == "1.2.3.4"

    def test_read_meta_no_versioninfo(self):
        pe = self.tmp / "bare.exe"
        pe.write_bytes(_make_minimal_pe())
        assert read_meta(pe) == {}

    # rip_meta
    def test_rip_meta_saves_file(self):
        pe = self._pe("s.exe")
        out = rip_meta(pe)
        assert out.exists()
        assert out.suffix == ".meta"
        # saved bytes decode to the same fields
        from keymaker.steal import _extract_meta_strings

        assert _extract_meta_strings(out.read_bytes())["CompanyName"] == "Acme Corp"

    def test_rip_meta_custom_output(self):
        pe = self._pe("s.exe")
        out = self.tmp / "custom.meta"
        rip_meta(pe, out)
        assert out.exists()

    def test_rip_meta_no_versioninfo_raises(self):
        pe = self.tmp / "bare.exe"
        pe.write_bytes(_make_minimal_pe())
        with pytest.raises(ValueError, match="no VS_VERSION_INFO"):
            rip_meta(pe)

    # graft_with_meta
    def test_graft_with_meta_grafts_sig(self):
        src = self._pe("src.exe", signed=True)
        tgt = self._pe("tgt.exe", signed=False)
        out, _ = graft_with_meta(src, tgt)
        assert check(out) is True

    def test_graft_with_meta_grafts_versioninfo(self):
        # src has fewer/shorter fields so its wLength <= tgt wLength
        vi_src = _make_versioninfo_bytes({"CompanyName": "Legit Inc"})
        vi_tgt = _make_versioninfo_bytes(
            {
                "CompanyName": "ImplantCo",
                "ProductName": "Implant",
                "FileVersion": "0.0.0.1",
            }
        )
        src = self.tmp / "src.exe"
        tgt = self.tmp / "tgt.exe"
        src.write_bytes(_make_pe_with_vi(vi_src, signed=True))
        tgt.write_bytes(_make_pe_with_vi(vi_tgt, signed=False))
        out, meta_ok = graft_with_meta(src, tgt)
        assert meta_ok is True
        fields = read_meta(out)
        assert fields["CompanyName"] == "Legit Inc"

    def test_graft_with_meta_skips_meta_when_target_has_none(self):
        src = self._pe("src.exe", signed=True)
        tgt_bare = self.tmp / "bare.exe"
        tgt_bare.write_bytes(_make_minimal_pe())
        out, meta_ok = graft_with_meta(src, tgt_bare)
        assert meta_ok is False
        assert check(out) is True  # PKCS#7 still grafted

    def test_graft_with_meta_unsigned_source_raises(self):
        src = self._pe("src_unsigned.exe", signed=False)
        tgt = self._pe("tgt.exe", signed=False)
        with pytest.raises(ValueError, match="not signed"):
            graft_with_meta(src, tgt)

    # CLI: steal meta
    def test_steal_meta_cli_prints_fields(self, capsys):
        pe = self._pe("m.exe")
        rc = main(["steal", "meta", str(pe)])
        assert rc == 0
        captured = capsys.readouterr().out
        assert "Acme Corp" in captured

    def test_steal_meta_cli_missing_file(self, capsys):
        rc = main(["steal", "meta", "/nonexistent.exe"])
        assert rc == 0  # per-file, doesn't abort

    def test_steal_meta_cli_no_versioninfo(self, capsys):
        pe = self.tmp / "bare.exe"
        pe.write_bytes(_make_minimal_pe())
        main(["steal", "meta", str(pe)])
        out = capsys.readouterr().out
        assert "no VS_VERSION_INFO" in out


# ── vendors ───────────────────────────────────────────────────────────────────


class TestVendors:
    def test_pools_non_empty(self):
        for name, pool in vendors.POOLS.items():
            assert len(pool) >= 10, f"{name} pool too small"

    def test_all_contains_sublists(self):
        for v in vendors.ENTERPRISE:
            assert v in vendors.ALL
        for v in vendors.BANKING:
            assert v in vendors.ALL
        for v in vendors.FRENCH:
            assert v in vendors.ALL
        for v in vendors.GENERIC:
            assert v in vendors.ALL

    def test_pool_keys(self):
        assert set(vendors.POOLS) == {
            "enterprise",
            "banking",
            "french",
            "generic",
            "all",
        }

    def test_enterprise_contains_cisco(self):
        assert "Cisco Systems" in vendors.ENTERPRISE

    def test_banking_contains_thales(self):
        assert "Thales Group" in vendors.BANKING

    def test_french_contains_wavestone(self):
        assert "Wavestone SAS" in vendors.FRENCH

    def test_generic_contains_synapse(self):
        assert "Synapse Software Ltd" in vendors.GENERIC

    def test_no_duplicates_within_pool(self):
        for name, pool in vendors.POOLS.items():
            assert len(pool) == len(set(pool)), f"{name} has duplicates"


# ── ui ────────────────────────────────────────────────────────────────────────


class TestUI:
    def test_ok_contains_checkmark(self):
        assert "✓" in ok("test")

    def test_err_contains_cross(self):
        assert "✗" in err("test")

    def test_info_contains_arrow(self):
        assert "→" in info("test")

    def test_warn_contains_exclamation(self):
        assert "!" in warn("test")

    def test_heading_not_empty(self):
        h = heading("KeyMaker")
        assert "KeyMaker" in h

    def test_table_has_headers(self):
        t = table(["A", "B"], [["x", "y"], ["1", "2"]])
        assert "A" in t and "B" in t
        assert "x" in t and "y" in t

    def test_table_separator_line(self):
        t = table(["COL1", "COL2"], [["a", "b"]])
        lines = t.splitlines()
        assert len(lines) >= 3  # header, sep, row
        assert "--" in lines[1]

    def test_table_column_width_padded(self):
        t = table(["SHORT", "LONGERHEADER"], [["a", "b"]])
        assert "LONGERHEADER" in t


# ── sign helpers ──────────────────────────────────────────────────────────────


class TestSignHelpers:
    def test_timestamp_servers_list(self):
        assert len(TIMESTAMP_SERVERS) >= 3
        for ts in TIMESTAMP_SERVERS:
            assert ts.startswith("http")

    def test_pick_ts_returns_string(self):
        ts = _pick_ts()
        assert isinstance(ts, str)
        assert ts in TIMESTAMP_SERVERS

    def test_verify_pe_not_found(self):
        with patch("keymaker.sign._osslsigncode", return_value="/usr/bin/osslsigncode"):
            with patch("keymaker.sign.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=1, stdout="", stderr="not found"
                )
                result = verify_pe(Path("/nonexistent/file.exe"))
                assert result["signed"] is False

    def test_verify_pe_signed_output(self):
        with patch("keymaker.sign._osslsigncode", return_value="/usr/bin/osslsigncode"):
            with patch("keymaker.sign.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0, stdout="Signature verification: ok\n", stderr=""
                )
                result = verify_pe(Path("/fake/signed.exe"))
                assert result["signed"] is True

    def test_verify_pe_unsigned_output(self):
        with patch("keymaker.sign._osslsigncode", return_value="/usr/bin/osslsigncode"):
            with patch("keymaker.sign.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=1, stdout="No signature found\n", stderr=""
                )
                result = verify_pe(Path("/fake/unsigned.exe"))
                assert result["signed"] is False

    def test_osslsigncode_not_found_raises(self):
        with patch("shutil.which", return_value=None):
            from keymaker.sign import _osslsigncode

            with pytest.raises(RuntimeError, match="osslsigncode not found"):
                _osslsigncode()


# ── cert (integration, requires openssl) ─────────────────────────────────────


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
class TestCertIntegration:
    def setup_method(self):
        self.tmp = Path(tempfile.mkdtemp())

    def teardown_method(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_gen_cert_creates_pfx(self):
        out = self.tmp / "test.pfx"
        gen_cert(
            "CN=Test Corp,O=Test Corp,C=US",
            days=30,
            key_bits=2048,
            out_pfx=out,
            pfx_pass="",
        )
        assert out.exists()
        assert out.stat().st_size > 0

    def test_gen_cert_with_password(self):
        out = self.tmp / "test_pass.pfx"
        gen_cert(
            "CN=Test,O=Test,C=US",
            days=30,
            key_bits=2048,
            out_pfx=out,
            pfx_pass="hunter2",
        )
        assert out.exists()

    def test_cert_info_extracts_subject(self):
        out = self.tmp / "info.pfx"
        gen_cert(
            "CN=Cisco Systems,O=Cisco Systems,C=US", days=30, key_bits=2048, out_pfx=out
        )
        info = _cert_info(out)
        assert info is not None
        assert "Cisco" in (info.get("subject") or "")

    def test_cert_info_extracts_expires(self):
        out = self.tmp / "exp.pfx"
        gen_cert("CN=Test,O=Test,C=US", days=30, key_bits=2048, out_pfx=out)
        info = _cert_info(out)
        assert info is not None
        assert info.get("expires") != ""

    def test_cert_info_none_on_invalid(self):
        fake = self.tmp / "fake.pfx"
        fake.write_bytes(b"not a pfx")
        assert _cert_info(fake) is None

    def test_import_pfx_copies_file(self):
        src = self.tmp / "src.pfx"
        gen_cert("CN=Test,O=Test,C=US", days=30, key_bits=2048, out_pfx=src)
        dst = self.tmp / "imported.pfx"
        import_pfx(src, dst)
        assert dst.exists()

    def test_import_pfx_invalid_raises(self):
        bad = self.tmp / "bad.pfx"
        bad.write_bytes(b"garbage")
        dst = self.tmp / "dst.pfx"
        with pytest.raises(subprocess.CalledProcessError):
            import_pfx(bad, dst)

    def test_list_certs_empty(self):
        assert list_certs(self.tmp) == []

    def test_list_certs_finds_pfx(self):
        out = self.tmp / "found.pfx"
        gen_cert("CN=Found,O=Found,C=US", days=30, key_bits=2048, out_pfx=out)
        certs = list_certs(self.tmp)
        assert len(certs) == 1
        assert certs[0]["file"] == "found.pfx"

    def test_gen_cert_sha384_digest(self):
        out = self.tmp / "sha384.pfx"
        gen_cert(
            "CN=Test,O=Test,C=US", days=30, key_bits=2048, out_pfx=out, digest="sha384"
        )
        assert out.exists()

    def test_gen_cert_3072_bits(self):
        out = self.tmp / "rsa3072.pfx"
        gen_cert("CN=Test,O=Test,C=US", days=30, key_bits=3072, out_pfx=out)
        assert out.exists()


# ── store ─────────────────────────────────────────────────────────────────────


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
class TestStore:
    def setup_method(self):
        self.tmp = Path(tempfile.mkdtemp())

    def teardown_method(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_pfx(self, name="test") -> Path:
        out = self.tmp / f"{name}_src.pfx"
        gen_cert(f"CN={name},O={name},C=US", days=30, key_bits=2048, out_pfx=out)
        return out

    def test_add_and_get(self):
        pfx = self._make_pfx("corp")
        alias = add(pfx, alias="corp", root=self.tmp)
        assert alias == "corp"
        entry = get("corp", root=self.tmp)
        assert entry is not None
        assert "corp" in (entry.get("subject") or "")

    def test_add_auto_alias(self):
        pfx = self._make_pfx("autotest")
        alias = add(pfx, root=self.tmp)
        assert alias == "autotest_src"

    def test_remove_existing(self):
        pfx = self._make_pfx("rm")
        add(pfx, alias="rm", root=self.tmp)
        assert remove("rm", root=self.tmp) is True
        assert get("rm", root=self.tmp) is None

    def test_remove_nonexistent(self):
        assert remove("doesnotexist", root=self.tmp) is False

    def test_list_all_empty(self):
        assert list_all(root=self.tmp) == []

    def test_list_all_populated(self):
        pfx = self._make_pfx("listed")
        add(pfx, alias="listed", root=self.tmp)
        entries = list_all(root=self.tmp)
        assert len(entries) == 1
        assert entries[0]["alias"] == "listed"

    def test_newest_empty_store(self):
        pfx, pw = newest(root=self.tmp)
        assert pfx is None

    def test_newest_returns_most_recent(self):
        pfx = self._make_pfx("recent")
        add(pfx, alias="recent", root=self.tmp)
        p, _ = newest(root=self.tmp)
        assert p is not None
        assert p.name == "recent.pfx"


# ── cli parser ────────────────────────────────────────────────────────────────


class TestCLIParser:
    def setup_method(self):
        self.p = build_parser()

    def test_gen_defaults(self):
        args = self.p.parse_args(["gen"])
        assert args.cmd == "gen"
        assert args.pool == "enterprise"
        assert args.cn is None

    def test_gen_with_cn(self):
        args = self.p.parse_args(["gen", "--cn", "MyVendor"])
        assert args.cn == "MyVendor"

    def test_gen_pool_banking(self):
        args = self.p.parse_args(["gen", "--pool", "banking"])
        assert args.pool == "banking"

    def test_sign_files(self):
        args = self.p.parse_args(["sign", "a.exe", "b.dll"])
        assert args.files == ["a.exe", "b.dll"]
        assert args.cmd == "sign"

    def test_sign_no_timestamp(self):
        args = self.p.parse_args(["sign", "x.exe", "--no-timestamp"])
        assert args.no_timestamp is True

    def test_batch_defaults(self):
        args = self.p.parse_args(["batch", "/some/dir"])
        assert args.dir == "/some/dir"
        assert args.recurse is False

    def test_batch_recurse(self):
        args = self.p.parse_args(["batch", "/dir", "-r"])
        assert args.recurse is True

    def test_import_pfx(self):
        args = self.p.parse_args(["import", "/tmp/cert.pfx"])
        assert args.pfx == "/tmp/cert.pfx"

    def test_verify_multiple(self):
        args = self.p.parse_args(["verify", "a.exe", "b.exe"])
        assert len(args.files) == 2

    def test_vendors_default(self):
        args = self.p.parse_args(["vendors"])
        assert args.pool is None

    def test_vendors_pool_french(self):
        args = self.p.parse_args(["vendors", "--pool", "french"])
        assert args.pool == "french"

    def test_no_subcommand_returns_0(self):
        rc = main([])
        assert rc == 0

    def test_gen_llm_flag_accepted(self):
        args = self.p.parse_args(["gen", "--llm", "ollama"])
        assert args.llm == "ollama"

    def test_gen_llm_context_flag_accepted(self):
        args = self.p.parse_args(
            ["gen", "--llm", "ollama", "--llm-context", "French banking sector"]
        )
        assert args.llm == "ollama"
        assert args.llm_context == "French banking sector"

    def test_gen_llm_defaults_empty(self):
        args = self.p.parse_args(["gen"])
        assert args.llm == ""
        assert args.llm_context == ""

    def test_gen_unit_flag_accepted(self):
        args = self.p.parse_args(["gen", "--unit", "Software Engineering"])
        assert args.unit == "Software Engineering"


# ── LLMProvider ───────────────────────────────────────────────────────────────


class TestLLMProvider:
    def test_invalid_provider_raises(self):
        from keymaker.llm import LLMProvider

        with pytest.raises(ValueError, match="Unknown LLM provider"):
            LLMProvider("notaprovider")

    def test_provider_model_defaults(self):
        from keymaker.llm import LLMProvider

        llm = LLMProvider("ollama")
        assert llm.provider == "ollama"
        assert llm.model == "llama3.2"

    def test_provider_model_override(self):
        from keymaker.llm import LLMProvider

        llm = LLMProvider("ollama:mistral")
        assert llm.model == "mistral"

    def test_generate_cert_profile_returns_none_when_network_fails(self):
        import random

        from keymaker.llm import LLMProvider

        llm = LLMProvider("ollama")
        with patch.object(llm, "_call_raw", return_value=None):
            result = llm.generate_cert_profile("enterprise", random.Random(42))
        assert result is None

    def test_generate_cert_profile_parses_clean_json(self):
        import json
        import random

        from keymaker.llm import LLMProvider

        llm = LLMProvider("ollama")
        payload = json.dumps(
            {
                "org": "Acme Systems SA",
                "unit": "Software Engineering",
                "country": "FR",
                "email": "cert@acme-systems.fr",
                "cn": "Acme Systems SA",
            }
        )
        with patch.object(llm, "_call_raw", return_value=payload):
            result = llm.generate_cert_profile("enterprise", random.Random(42))
        assert result is not None
        assert result["org"] == "Acme Systems SA"
        assert result["unit"] == "Software Engineering"
        assert result["country"] == "FR"
        assert "cn" in result

    def test_generate_cert_profile_parses_fenced_json(self):
        import json
        import random

        from keymaker.llm import LLMProvider

        llm = LLMProvider("deepseek")
        inner = json.dumps(
            {
                "org": "Nexus Corp",
                "unit": "R&D",
                "country": "US",
                "email": "code@nexus.io",
                "cn": "Nexus Corp",
            }
        )
        fenced = f"```json\n{inner}\n```"
        with patch.object(llm, "_call_raw", return_value=fenced):
            result = llm.generate_cert_profile("banking", random.Random(1))
        assert result is not None
        assert result["org"] == "Nexus Corp"

    def test_generate_cert_profile_extracts_embedded_json(self):
        import random

        from keymaker.llm import LLMProvider

        llm = LLMProvider("anthropic")
        raw = (
            'Sure! Here is the profile: {"org": "Delta Tech", "unit": "Dev",'
            ' "country": "DE", "email": "x@delta.de", "cn": "Delta Tech"} Hope that helps!'
        )
        with patch.object(llm, "_call_raw", return_value=raw):
            result = llm.generate_cert_profile("generic", random.Random(7))
        assert result is not None
        assert result["org"] == "Delta Tech"

    def test_generate_cert_profile_returns_none_on_invalid_json(self):
        import random

        from keymaker.llm import LLMProvider

        llm = LLMProvider("openai")
        with patch.object(llm, "_call_raw", return_value="this is not json at all"):
            result = llm.generate_cert_profile("enterprise", random.Random(0))
        assert result is None

    def test_generate_cert_profile_missing_org_key_returns_none(self):
        """JSON returned but lacks 'org' key → rejected."""
        import json
        import random

        from keymaker.llm import LLMProvider

        llm = LLMProvider("ollama")
        payload = json.dumps({"name": "Bad Corp", "unit": "IT"})
        with patch.object(llm, "_call_raw", return_value=payload):
            result = llm.generate_cert_profile("enterprise", random.Random(0))
        assert result is None

    def test_call_raw_returns_none_on_url_error(self):
        import random
        import urllib.error

        from keymaker.llm import LLMProvider

        llm = LLMProvider("ollama")
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            result = llm._call_raw("test prompt", random.Random(0))
        assert result is None


# ── LLM integration in CLI (mocked) ──────────────────────────────────────────


class TestCLILLMIntegration:
    @patch("keymaker.cli.main")
    def test_llm_flag_wired_without_crash(self, _mock_main, tmp_path, capsys):
        """Passing --llm with a bad provider raises ValueError via LLMProvider."""
        from keymaker.llm import LLMProvider

        with pytest.raises(ValueError, match="Unknown LLM provider"):
            LLMProvider("badprovider")

    @pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
    def test_cmd_gen_llm_fallback_uses_static_pool(self, tmp_path, capsys):
        """When LLM returns None, gen falls back to static pool (no crash)."""
        with patch("keymaker.llm.LLMProvider.generate_cert_profile", return_value=None):
            rc = main(
                [
                    "--store",
                    str(tmp_path),
                    "gen",
                    "--llm",
                    "ollama",
                    "--llm-context",
                    "test",
                    "--bits",
                    "2048",
                    "--days",
                    "30",
                ]
            )
        assert rc == 0
        assert any(tmp_path.glob("*.pfx"))

    @pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
    def test_cmd_gen_llm_profile_overrides_fields(self, tmp_path, capsys):
        """When LLM returns a profile, its fields appear in the generated cert."""
        profile = {
            "org": "Quantum Bridge SA",
            "unit": "Engineering",
            "country": "FR",
            "email": "cert@qb.fr",
            "cn": "Quantum Bridge SA",
        }
        with patch(
            "keymaker.llm.LLMProvider.generate_cert_profile", return_value=profile
        ):
            rc = main(
                [
                    "--store",
                    str(tmp_path),
                    "gen",
                    "--llm",
                    "ollama",
                    "--llm-context",
                    "French banking",
                    "--bits",
                    "2048",
                    "--days",
                    "30",
                ]
            )
        assert rc == 0
        pfxs = list(tmp_path.glob("*.pfx"))
        assert len(pfxs) == 1
        # slug derived from LLM-set CN
        assert "quantum_bridge_sa" in pfxs[0].stem


# ── cli commands (mocked) ─────────────────────────────────────────────────────


class TestCLICommands:
    def test_cmd_vendors_all(self, capsys):
        rc = main(["vendors", "--pool", "all"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Cisco Systems" in out
        assert "Thales Group" in out

    def test_cmd_vendors_banking(self, capsys):
        rc = main(["vendors", "--pool", "banking"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Worldline SA" in out

    def test_cmd_list_empty_store(self, tmp_path, capsys):
        rc = main(["--store", str(tmp_path), "list"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "no certificates" in out

    @pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
    def test_cmd_gen_creates_pfx(self, tmp_path, capsys):
        rc = main(
            [
                "--store",
                str(tmp_path),
                "gen",
                "--cn",
                "Test Corp",
                "--bits",
                "2048",
                "--days",
                "30",
            ]
        )
        assert rc == 0
        pfxs = list(tmp_path.glob("*.pfx"))
        assert len(pfxs) == 1

    def test_cmd_verify_missing_file(self, capsys):
        rc = main(["verify", "/nonexistent/file.exe"])
        assert rc == 1

    @patch("keymaker.sign._osslsigncode", return_value="/usr/bin/osslsigncode")
    @patch("keymaker.sign.subprocess.run")
    def test_cmd_verify_signed(self, mock_run, mock_ossl, tmp_path, capsys):
        fake_pe = tmp_path / "fake.exe"
        fake_pe.write_bytes(b"MZ\x00")
        mock_run.return_value = MagicMock(
            returncode=0, stdout="Signature verification: ok\n", stderr=""
        )
        rc = main(["verify", str(fake_pe)])
        assert rc == 0

    @patch("keymaker.sign._osslsigncode", return_value="/usr/bin/osslsigncode")
    @patch("keymaker.sign.subprocess.run")
    def test_cmd_verify_unsigned(self, mock_run, mock_ossl, tmp_path, capsys):
        fake_pe = tmp_path / "unsigned.exe"
        fake_pe.write_bytes(b"MZ\x00")
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="No signature"
        )
        rc = main(["verify", str(fake_pe)])
        assert rc == 1

    def test_cmd_import_missing_file(self, tmp_path, capsys):
        rc = main(["--store", str(tmp_path), "import", "/nonexistent.pfx"])
        assert rc == 1

    @pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
    def test_cmd_gen_and_list(self, tmp_path, capsys):
        main(
            [
                "--store",
                str(tmp_path),
                "gen",
                "--cn",
                "Listed Corp",
                "--bits",
                "2048",
                "--days",
                "30",
            ]
        )
        rc = main(["--store", str(tmp_path), "list"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "listed_corp" in out.lower()


# ── sign_ps1 ──────────────────────────────────────────────────────────────────


def _has_cryptography() -> bool:
    try:
        import cryptography  # noqa: F401

        return True
    except ImportError:
        return False


_SKIP_CRYPTO = pytest.mark.skipif(
    not _has_cryptography(),
    reason="cryptography package not installed",
)


class TestSignPs1:
    """Tests for sign_ps1() — PS1 Authenticode signature block injection."""

    @pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
    @_SKIP_CRYPTO
    def test_sign_ps1_appends_signature_block(self, tmp_path):
        """sign_ps1 must append the standard PowerShell signature block markers."""
        from keymaker.cert import gen_cert

        pfx = tmp_path / "test.pfx"
        gen_cert(
            "CN=TestCorp Root CA,O=TestCorp,C=US", days=30, key_bits=2048, out_pfx=pfx
        )
        ps1 = tmp_path / "payload.ps1"
        ps1.write_text('Write-Host "hello"', encoding="utf-8")
        sign_ps1(ps1, pfx)
        content = ps1.read_text(encoding="utf-8")
        assert "# SIG # Begin signature block" in content
        assert "# SIG # End signature block" in content

    @pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
    @_SKIP_CRYPTO
    def test_sign_ps1_original_content_preserved(self, tmp_path):
        """Original script content must appear before the signature block."""
        from keymaker.cert import gen_cert

        pfx = tmp_path / "test.pfx"
        gen_cert(
            "CN=TestCorp Root CA,O=TestCorp,C=US", days=30, key_bits=2048, out_pfx=pfx
        )
        original = 'Set-ExecutionPolicy Bypass\nInvoke-Expression "whoami"'
        ps1 = tmp_path / "payload.ps1"
        ps1.write_text(original, encoding="utf-8")
        sign_ps1(ps1, pfx)
        content = ps1.read_text(encoding="utf-8")
        sig_pos = content.index("# SIG # Begin signature block")
        assert original in content[:sig_pos]

    @pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
    @_SKIP_CRYPTO
    def test_sign_ps1_idempotent(self, tmp_path):
        """Calling sign_ps1 twice must not stack signature blocks."""
        from keymaker.cert import gen_cert

        pfx = tmp_path / "test.pfx"
        gen_cert(
            "CN=TestCorp Root CA,O=TestCorp,C=US", days=30, key_bits=2048, out_pfx=pfx
        )
        ps1 = tmp_path / "payload.ps1"
        ps1.write_text("whoami", encoding="utf-8")
        sign_ps1(ps1, pfx)
        sign_ps1(ps1, pfx)
        content = ps1.read_text(encoding="utf-8")
        assert content.count("# SIG # Begin signature block") == 1

    @pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
    @_SKIP_CRYPTO
    def test_sign_ps1_returns_target_path(self, tmp_path):
        from keymaker.cert import gen_cert

        pfx = tmp_path / "test.pfx"
        gen_cert(
            "CN=TestCorp Root CA,O=TestCorp,C=US", days=30, key_bits=2048, out_pfx=pfx
        )
        ps1 = tmp_path / "payload.ps1"
        ps1.write_text("Get-Date", encoding="utf-8")
        result = sign_ps1(ps1, pfx)
        assert result == ps1

    @pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
    @_SKIP_CRYPTO
    def test_sign_ps1_sig_lines_prefixed(self, tmp_path):
        """Every line inside the block must start with '# '."""
        from keymaker.cert import gen_cert

        pfx = tmp_path / "test.pfx"
        gen_cert(
            "CN=TestCorp Root CA,O=TestCorp,C=US", days=30, key_bits=2048, out_pfx=pfx
        )
        ps1 = tmp_path / "payload.ps1"
        ps1.write_text("Get-Date", encoding="utf-8")
        sign_ps1(ps1, pfx)
        content = ps1.read_text(encoding="utf-8")
        in_block = False
        for line in content.splitlines():
            if line == "# SIG # Begin signature block":
                in_block = True
                continue
            if line == "# SIG # End signature block":
                break
            if in_block:
                assert line.startswith("# "), f"unexpected line: {line!r}"
