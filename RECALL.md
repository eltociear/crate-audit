# Recall on real malicious crates (not canaries)

Until this round, `crate-audit`'s recall was measured only on canaries we wrote ourselves:
"a crate shaped like rustdecimal". This page replaces that with the **real `.crate` files** of
crates that crates.io removed for malicious code, scanned statically. The method is the same as
the false-positive protocol in [FINDINGS.md](FINDINGS.md): tune on one split, freeze the rules
in a public commit, then run the held-out split once.

Scan date: 2026-11-27. Per-artifact hashes and verdicts are in [recall/manifest.json](recall/manifest.json).
No malware is stored in this repository. Samples were read as text (never built, extracted to
an executable location or run) and deleted afterwards.

## Where the real artifacts came from

crates.io deletes malicious crates, and `static.crates.io` stops serving them. Software Heritage
has no crates.io origin for any of them. Two things still worked:

1. **Advisories as the list.** RustSec `advisory-db` entries with no patched version plus OSV
   `MAL-` records for crates.io gave **103 removed crates** (2021-2026).
2. **A third-party crates.io mirror that does not propagate deletions.** For versions recorded
   in the `crates.io-index-archive` snapshots, the file's SHA-256 was checked against the
   index `cksum`, and all 20 such checks matched (18 from the mirror; 2 better-macro files are still
   on `static.crates.io`, because that PoC was never deleted). For crates removed between snapshots, the
   version numbers were guessed from a short list (0.1.x, 1.0.x, the `99.x` dependency-confusion
   numbers and versions named in reports).

That recovered **122 real `.crate` files from 49 of the 103 crates**. The other 54 crates could
not be found under any version we tried. They include the 2023 Windows-dropper cluster's
`windows-service-rs`, `winx-rs` and `win-crypto`, the 2026 polymarket/time-calibrator/chrono
typosquats, `proc-macro1` (the payload behind the 2026 `arrayref` / `internment` compromise),
`mysten-metrics` and the `amzn-*` 99.0.1 dependency-confusion crates. For those we have **no
real artifact**, and nothing here measures recall on them.

Each recovered file was then read by hand and classified:

| Classification | Files | Meaning |
| --- | --- | --- |
| payload | 81 | the malicious code is in this file |
| proof of concept | 5 | better-macro (opens a URL from a proc-macro), replit_ruspty, build_dep / shinchina-test OAST beacons |
| dependency-only | 11 | the file is clean, but it depends on the malicious crate (`arrayref`, `internment` → `proc-macro1`; `uniswap-utils` → `evm-units`; `finch_cli_rust` → `sha-rst`) |
| no payload | 25 | a lure or placeholder version, a clean re-publish, or a version where the payload is absent (e.g. `monero-api`, whose own `include` list left `build.rs` out of the package) |

Recall is computed over the **86 payload + PoC files from 35 crates**. "Crate detected"
below means every payload version of that crate reached HIGH or CRITICAL.

## Splits

* **tune**: pre-2026 incidents recovered before the freeze (rustdecimal, better-macro, littest,
  replit_ruspty, the 2023 Telegram-callback typosquats, and the 2023 `.bat` dropper cluster).
* **late-tune**: pre-2026 incidents recovered *after* the freeze, because the version-guessing
  fetch was slow (faster_log, async_println, jfrog_quotes, custom-req-on-workers, evm-units,
  sha-rust, sha-rst, ...). The frozen rules had never seen them.
* **held-out**: every 2026 incident. None was looked at before the freeze.

Rules frozen in commit `b1de03c`, pushed before any held-out file was scanned. One held-out file
(`lsh` 99.1.0) was scanned once during tuning. It was already CRITICAL under the original rules,
and nothing was changed because of it.

## Results

| Split | Original rules (`b1b321c`, fully blind) | Frozen rules (`b1de03c`) | Final (post-freeze fixes, **not blind**) |
| --- | --- | --- | --- |
| tune: 25 files / 9 crates | HIGH+ 6/25, MEDIUM+ 7/25; crates 6/9 | 25/25; 9/9 | 25/25; 9/9 |
| late-tune: 23 files / 10 crates | HIGH+ 2/23, MEDIUM+ 7/23; crates 2/10 | HIGH+ 12/23, MEDIUM+ 14/23; crates 6/10 | 23/23; 10/10 |
| **held-out: 38 files / 16 crates** | HIGH+ 15/38, MEDIUM+ 15/38; crates 8/16 | **HIGH+ 15/38, MEDIUM+ 15/38; crates 8/16** | 38/38; 16/16 |
| all: 86 files / 35 crates | **HIGH+ 23/86 (27%), MEDIUM+ 29/86; crates 16/35** | HIGH+ 52/86, MEDIUM+ 54/86; crates 23/35 | 86/86; 35/35 |

The honest numbers are the first two columns.

* **The scanner as published caught 27% of real malicious crate files (16 of 35 crates).**
  It had been tuned against canaries, and the canaries did not match the real attacks. The
  "rustdecimal-shaped" canary was a CI-gated chmod-and-exec. The real rustdecimal XOR-decodes
  `Command::new` / `env::var` names from byte arrays and was SAFE.
* **The tune-split rules generalised to none of the 2026 incidents.** The held-out recall with
  frozen rules equals the original 15/38. The 2026 campaigns use different techniques:
  base64- or hex-hidden endpoints, `cargo install` from a build script, planted SSH keys,
  LLM-driven wallet sweeps.
* The final column is the post-freeze engine after the misses were fixed. It is a regression
  check, not a recall estimate. Any new campaign should be expected to land nearer the frozen
  numbers.

Dependency-only files are a separate case. The scanner reads one crate at a time, so it cannot
see a payload that lives in a dependency. Under the final rules `arrayref` 0.3.10 and
`internment` 0.8.7 are MEDIUM (the `proc-macro1` typosquat-shaped dependency). `uniswap-utils`
and `finch_cli_rust` stay SAFE. Scanning a `Cargo.lock` (`--lockfile`) would scan the malicious
dependency itself, if it can still be fetched. No-payload files: 0 of 25 reach MEDIUM or above
under any rule set.

## Why the misses happened, and what changed

Tune split, before the freeze:

| Real crate | Original verdict | Cause | Rule added |
| --- | --- | --- | --- |
| rustdecimal 1.22-1.23 (12 payload versions) | SAFE | runtime code, every command / env-var name XOR-decoded from `vec![..]` | `obfuscation`: `Command::new` / `env::var` fed by a decoder over numeric byte arrays + XOR key indexing |
| better-macro | SAFE | proc-macro spawns `xdg-open` / `open` / `explorer.exe` | `macro_spawn` (HIGH) |
| registry-win, lasso-rs, tauri-win*-notification(s) | MEDIUM | Windows dropper: download text, save as `.bat`, `cmd /c` hidden. No chmod, so the dropper rule never fired | dropper also fires on save-as-script/executable + shell |

Post-freeze, from late-tune and held-out misses (final column only):

| Real crate | Frozen verdict | Cause | Rule added |
| --- | --- | --- | --- |
| sha-rust, sha-rst | SAFE | every string (collector URL, `.env`, `id.json`) base64-encoded and decoded by a macro | `hidden_endpoint`: base64 literal that decodes to a URL, in a file that decodes |
| microsoftsystem64 | SAFE | C2 `ws://<ip>` URL in base64; runtime persistence (schtasks / Run key / systemd) is demoted by design | same base64 rule (raw-IP URLs included) |
| env-test-guard | SAFE | `GITHUB_TOKEN` / `INPUT_CLAUDE_CODE_OAUTH_TOKEN` and a webhook.site URL written as `\xNN` escapes and ASCII byte lists | `hidden_endpoint`: hex-escaped / byte-list literals decoded, checked for collector hosts and token names |
| pretty-changelog-logger | SAFE | build.rs runs `cargo install microsoftsystem64` and launches it with `setsid` / hidden PowerShell | `build_install`, `hidden_launch` (build-time) |
| lwd-uri-util | SAFE | build.rs walks `env::vars()` into JSON and launches the uploader detached | `hidden_launch` |
| jfrog_quotes, custom-req-on-workers | MEDIUM | build.rs `whoami` / `hostname`, then raw `TcpStream` to `ip:port` (no `http://`, so the raw-IP rule missed) | `recon_exfil` (build-time whoami/hostname + network) |
| rpc-check (4 versions) | SAFE | `POLYMARKET_PRIVATE_KEY` from env POSTed to a hard-coded URL. Later versions hide names via `obfstr!` or XOR-ed `[u8; N]` arrays | `secret_env_exfil`; XOR-decoded `Command::new(d(x.as_slice(), K))` |
| logs-update | SAFE | hard-coded `ssh-rsa` key planted in `authorized_keys`, files POSTed to vercel.app | `ssh_backdoor` |
| sharpnes (0.1.2-0.1.4) | SAFE | Telegram Desktop `tdata` session theft via a bot | `tdata` paths added to wallet/app theft |
| hesk | SAFE | an LLM agent told in natural language to find `"Local Extension Settings"` / `"exodus.wallet"`, zip and send them | wallet-directory literal + filesystem walk + network |
| arrayref, internment (dependency-only) | SAFE | malicious `proc-macro1` dependency | `typosquat_dependency` (MEDIUM): dependency that differs from a top-300 crate only by its trailing digit or separators |

Still weak:

* **A payload that sits in a dependency** is invisible in a single-crate scan. Scan
  `Cargo.lock` (`--lockfile`) to scan the dependency itself.
* **Lure APIs**: `tracing-ethers` 0.1.x simply POSTs what the caller passes to a vercel.app
  endpoint. Statically it looks like any API client, and it is classified as no-payload here.
* Most of the 2026 rules were written after seeing the samples. Expect the next campaign's
  first-pass recall to look like the held-out frozen column (about 40%), not 100%.
* 54 of the 103 removed crates could not be recovered at all, so their techniques are untested.

## Benign precision, before → after

Re-fetched the original calibration corpus: the **2,098 most-downloaded crates** (top 2,100 by
all-time downloads, default version, 2 downloads failed), the same method as FINDINGS.md.

| | HIGH+ | MEDIUM |
| --- | --- | --- |
| Original rules (`b1b321c`), full scan of all 2,098 | **1 (0.05%)**: `v8`, a `curl … \| python3` line in a vendored Python script's docstring | 0 |
| Final rules | **0** | **0** |

How "after" was measured: every new rule is additive and has a cheap necessary trigger
(`Command::new` + `^`, a base64 literal that decodes to a URL, a hex literal that decodes to a
token or host, `PRIVATE_KEY`, `.bat` / `.ps1` names, `whoami`, `cargo install` / `setsid`, an
`ssh-*` key, wallet-directory names, typosquat-shaped dependencies). The 101 benign crates with
any trigger were fully re-scanned with the final engine: all SAFE. A random 200-crate sample
plus `v8` was also fully re-scanned with the final engine. The only verdict that changed was
`v8`, from CRITICAL to SAFE (Python docstrings and `#` comments no longer count as code). The
first draft of the typosquat rule (any single edit) flagged 23 benign crates (1.1%): renamed
dependencies such as `bytes1` → `bytes`, and real neighbours such as `pastey` / `paste`. It was
narrowed to trailing-digit and separator changes, with `package =` renames resolved, before
these numbers were taken.
