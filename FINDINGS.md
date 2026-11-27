# What we found scanning the 1,599 most-downloaded Rust crates

This is the research behind `crate-audit`: a real scan of the top of crates.io, run with this
exact engine, calibrated so that "clean" means clean before any number is reported. Same method
as [mcp-audit](https://github.com/eltociear/mcp-audit/blob/main/FINDINGS.md) and
[npm-audit](https://github.com/eltociear/npm-audit/blob/main/FINDINGS.md).


> **2026-11-27 update:** recall is now measured on real malicious `.crate` files, not only on our
> canaries. See [RECALL.md](RECALL.md). A re-fetch of the top 2,098 crates scored 1 HIGH+
> before the wave-5 fixes (a docstring in `v8`'s vendored Python) and 0 after.

## Method

1. Listed the top 1,600 crates by all-time downloads from the crates.io API (`sort=downloads`,
   at 1 request per second) and took each crate's default version.
2. Downloaded each `.crate` from `static.crates.io` and read it as text. Nothing was built,
   compiled or executed. 1,599 were scanned; one download failed repeatedly on a flaky network.
3. For each crate, worked out which files run during `cargo build`: the build script (`build.rs`
   or the `build =` path in `Cargo.toml`) plus every module it pulls in through `mod`, `#[path]`
   and `include!`, and the whole `src/` of proc-macro crates. Runtime `src/` was scanned too.
   `tests/`, `benches/`, `examples/` and `fuzz/` were skipped because dependents don't compile them.
4. **Calibration set:** ranks 1-800. **Held-out set:** ranks 801-1,600, scanned with the engine
   as it stood after calibration.

Scan date: 2026-11-25.

## Headline

| Result | Calibration (800) | Held-out (799) |
| --- | --- | --- |
| Context-blind pass, HIGH+ | 45 (5.6%) | 29 (3.6%) |
| `crate-audit`, first pass | 0 | **1 (0.13%)** |
| `crate-audit`, final | **0** | **0** |
| Fetch errors | 0 | 1 |

**The most-downloaded part of crates.io, as published right now, is clean by every
malicious-pattern rule here.** That is the expected result, and it is what makes the scanner
usable. A CRITICAL on a crate you have never heard of means something only if the crates you
already depend on don't trip it.

The one held-out hit was a real bug, fixed before the final run, and the final held-out number
is therefore no longer blind. The reverse-shell rule's "socket handed to a process's stdio" leg
also matched `TcpStream::from_raw_fd(x.as_raw_fd())`, which re-wraps a socket. That file also
connects a socket and spawns `sh` for an unrelated reason, so all three legs fired. The leg now
requires `Stdio::from_raw_fd` / `Stdio::from(socket)`. One more calibration bug: `transfer\.sh`
(a file-drop host) matched `DataTransfer.ShareTarget` in a large bindings crate. Host patterns
are now word-anchored.

## How much of the top of crates.io runs code at build time

| | Crates | Share of 1,599 |
| --- | --- | --- |
| Has a build script | 217 | 13.6% |
| Is a proc-macro crate | 140 | 8.8% |
| **Either: runs code during `cargo build`** | **346** | **21.6%** |
| Declares `links =` (native library) | 33 | 2.1% |
| Build script split across several files | 17 | |

One in five of the most-used crates runs code on your machine just by being in your dependency
tree. That code runs before your tests, before your binary and before any runtime sandbox you
might have, as your user and with your CI secrets in the environment.

## What build-time code actually does

| Capability (in build-time files) | Crates | |
| --- | --- | --- |
| Reads environment variables | 179 | `TARGET`, `OUT_DIR`, `CARGO_FEATURE_*`, `RUSTC` |
| Spawns a process | 53 | Mostly `rustc --version` (feature detection). Then `git`, wrappers, `pkg-config`, `bindgen` |
| Native build (`cc` / `cmake` / `pkg-config` / `bindgen`) | 42 | |
| Embeds large byte arrays / `include_bytes!` | 5 | Tables and generated data |
| Walks the **whole** environment (`for (k, v) in env::vars()`) | 2 | Looking for `CARGO_FEATURE_*` / `DEP_*` keys |
| **Network I/O** | **0** | |

**No build script among the top 1,599 crates touches the network.** In npm, prebuilt-binary
downloads at install time are routine (34 of the 83 install-script packages we looked at). In
Rust, the popular `*-sys` crates in this set vendor or build their C sources, or find a system
library through `pkg-config`. That makes a **build-time download a much stronger signal in Rust
than in npm**. `crate-audit` still allows it when the file verifies a checksum, and reports it at
MEDIUM when it doesn't.

Proc-macros are quieter still. Of the 140, the only code that runs a process at expansion time
calls `rustfmt` on the code it generated. The other `Command::new` matches in proc-macro crates
were either *quoted*, meaning tokens the macro emits rather than runs, or in test-only files.
None does network I/O.

## The noise: what looks dangerous in a build script but isn't

The context-blind pass flagged **74 of 1,599 (4.6%)**. Every one was a false positive:

| Signal | Crates | Why it's noise |
| --- | --- | --- |
| Build script spawns a process | 53 | `rustc --version`, `git rev-parse`, compiler wrappers |
| Whole-environment walk (`env::vars()`) | 13 in all code, 3 in build scripts | Feature / dependency-metadata discovery. The risk is walking it **and sending it** |
| TLS verification disabled | 8 | TLS libraries exposing `danger_accept_invalid_certs` as an option, and their tests |
| Raw-IP URLs | 2 | Cloud metadata endpoints in runtime SDK code |

The lesson is the same as for MCP servers and npm: **these are capabilities, not attacks.** The
attack is a **combination**: the environment walk in a file that also POSTs, the
`credentials.toml` read next to a webhook, the download that is `chmod`ed and run, the key regex
next to an HTTP client. `crate-audit` scores only those.

## Known crates.io incidents, and the shape each one has

These are public, already-removed incidents. Each has an inert canary in `tests/fixtures/` that
fires at the right severity.

- **rustdecimal (2022, RUSTSEC-2022-0042):** a typosquat of `rust_decimal`. Its runtime code
  checked for `GITLAB_CI`, downloaded a binary, made it executable and ran it. That is the
  `dropper` shape, gated on a CI variable, and scores CRITICAL.
- **2023 typosquat batch:** a set of crates imitating popular names that reported host details
  to a Telegram bot. That is the `exfil_host` shape (`api.telegram.org/bot`) plus a network sink.
- **faster_log / async_println (2025):** typosquats of a logging crate. They scanned the text
  passing through them for Solana / Ethereum private-key patterns and POSTed matches to a
  Cloudflare Workers endpoint. That is the `key_harvest` shape: a 64-hex or base58 key regex
  plus a network sink in the same file.

The other canaries cover the build-time shapes the Rust supply chain hasn't (publicly) been hit
with yet, but npm has. They include pipe-to-shell from `build.rs`, environment dumps, `.bashrc`
persistence, a socket-to-shell reverse shell, an XOR-decoded embedded payload, `cargo publish`
with a stolen token (worm), and a proc-macro that beacons out at expansion time.

## Takeaways

1. **`cargo audit` passing tells you nothing about malice.** It covers what has already been
   reported. Scan new and changed dependencies for behaviour:
   `crate_audit.py --lockfile Cargo.lock --build-only` on every lockfile change.
2. **21.6% of top crates run code at build time.** Only those are scanned under build-time
   escalation; the other 78% can't do anything until you run your program.
3. **Network at build time is rare enough to treat as a review trigger.** None of the 217 popular
   build scripts here do it.
4. **Typosquats are the delivery mechanism.** All three incidents above imitated a popular name.
   Check the spelling of new dependencies before you scan them.

---

Run it yourself: `python crate_audit.py <crate>` or `python crate_audit.py --lockfile Cargo.lock`.

*Findings are pattern matches warranting human review, not verdicts. No crate in the scanned
corpus is accused of anything. Report suspected malicious crates to the crates.io team
(help@crates.io) and to RustSec, not as unverified public accusations.*
