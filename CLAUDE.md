# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`kcapi` is the official high-level Rust binding for `libkcapi`, a userspace interface to the Linux Kernel Cryptographic API (KCAPI / AF_ALG sockets). It wraps the unsafe FFI exposed by the `kcapi-sys` crate (a git submodule) in a safe, idiomatic Rust API. Because it targets the Linux kernel crypto API, **the crate only builds and its tests only pass on Linux with an appropriately configured kernel** (see Kernel requirements below).

## Build, test, lint

```sh
cargo build
cargo test                       # sanity tests in src/test/test_*.rs
cargo test md::                  # run one module's tests (substring filter)
cargo fmt --all -- --check       # CI enforces formatting
cargo clippy -- -D warnings      # CI treats all clippy warnings as errors
```

CI (`.github/workflows/main.yml`) runs build → test → fmt check → clippy, all gating. Match those before considering a change done.

### Submodule (critical)

`kcapi-sys/` is a git submodule and is **empty on a plain clone** — builds fail until it is checked out:

```sh
git submodule update --init --recursive   # or clone with --recurse-submodules
```

### Build prerequisites

Native build deps (the `vendored-kcapi` feature compiles libkcapi from source via autotools, and bindgen needs libclang):

- Autotools: `autoconf`, `automake` (`autotools-dev`), `libtool` — libkcapi's `configure.ac` uses `LT_INIT`, so libtool is required, not optional.
- bindgen: `llvm-dev` **and** `libclang-dev` — `llvm-dev` alone only provides `libclang-cpp.so`; bindgen needs the C API `libclang.so` from `libclang-dev`.
- If bindgen can't find libclang: `export LLVM_CONFIG_PATH=/usr/bin/llvm-config` (or set `LIBCLANG_PATH`).

Debian/Ubuntu one-liner: `sudo apt-get install -y autoconf automake libtool llvm-dev libclang-dev`

### Cargo features

- `vendored-kcapi` (default) — build & statically link libkcapi from the submodule source.
- `local-kcapi` — link against a system-installed libkcapi instead.
- `asym` (default) — enable the `akcipher` module. It is feature-gated because the asymmetric KCAPI requires out-of-tree kernel patches; the module and its tests (`#[cfg(feature = "asym")]`) compile out when disabled.

## Kernel requirements

Tests exercise real kernel crypto sockets, so the running kernel must have the `CONFIG_CRYPTO_USER*` options enabled (HASH, SKCIPHER, RNG, AEAD; plus `AKCIPHER` for the `asym` feature, `RNG_CAVP` for RNG CAVP tests). See README.md / lib.rs module docs for the full list. Missing kernel support shows up as runtime errors from the kernel, not compile errors.

## Architecture

`src/lib.rs` is the crate root. It defines the cross-cutting types that every module returns or consumes:

- `KcapiResult<T>` = `Result<T, KcapiError>` — the return type of essentially every public API.
- `KcapiError { code: i32, message: String }` — errno-style code plus message; implements `Display` and `std::error::Error`.
- `IOVec<T>` / `IOVecTrait` — safe wrapper over a kernel scatter/gather list (`Vec<Vec<u8>>` → `iovec`), used by AIO and streaming paths.
- `VMSplice` trait — splice-buffer sizing, implemented by ciphers.
- Access-mode constants (`ACCESS_HEURISTIC`, `ACCESS_SENDMSG`, `ACCESS_VMSPLICE`, `INIT_AIO`) re-exported from `kcapi_sys`.

Each cryptographic capability is its own module: `md` (digests/HMAC), `skcipher` (symmetric), `aead`, `rng`, `akcipher` (asym, gated), `kdf`. `util` holds shared helpers (`pad_iv`, `lib_version`).

**Every module follows the same two-layer shape — learn it once and it transfers:**

1. **A context struct** (`KcapiHash`, `KcapiSKCipher`, `KcapiAEAD`, `KcapiRNG`, `KcapiAKCipher`, `KcapiKDF`) holding a raw `kcapi_handle` pointer from the FFI. Construction is `::new(algorithm, ...)` where `algorithm` is a kernel cipher name from `/proc/crypto` (e.g. `"sha1"`, `"cbc(aes)"`, `"gcm(aes)"`). Keys/IVs/state are set via methods (`setkey`, `setentropy`, …), the operation runs (`encrypt`/`decrypt`/`digest`/`update`+`finalize`/`generate`/`sign`/`verify`), and a `Drop` impl frees the handle. This is the full-control path (streaming, AIO, scatter/gather).

2. **Module-level convenience free functions** that wrap the struct lifecycle into one call: `md::digest(alg, input)`, `md::sha256(input)`, `md::hmac_sha256(input, key)`, `skcipher::encrypt(alg, key, pt, iv)`, `skcipher::enc_aes_cbc(...)`, `rng::get_bytes(count)`, `kdf::hkdf(...)`, etc. These are what most consumers use.

When adding a new algorithm/operation, mirror this pattern: extend the context struct with a method for the full-control path, then (optionally) add a thin convenience wrapper, and add sanity tests in `src/test/test_<module>.rs` (registered in `src/test/mod.rs`).

### FFI boundary conventions

- All `unsafe` FFI calls go through `kcapi_sys::*`. Negative return codes are kernel errnos — convert them into `KcapiError` with the code and a descriptive message rather than panicking.
- Buffers cross the boundary as `Vec<u8>` / `*mut c_void`; sizes use `kcapi_sys::size_t`. Be careful that any `Vec` whose pointer is handed to the kernel outlives the call (see how `IOVec` retains `data`).
- Raw handles are not `Send`/`Sync` by default; where a type is made `Send` it is an explicit `unsafe impl` (e.g. `KcapiHash`) — preserve that reasoning if you touch threading.

## FFI coverage status and follow-ups

Every distinct **algorithm** libkcapi exposes a convenience function for now has a safe wrapper: digests/HMAC incl. SM3, symmetric ciphers incl. SM4 (CBC/CTR), AEAD, RNG, akcipher, KDF, and KPP (DH/ECDH). To find the gap, diff the generated FFI surface against what the safe crate calls:

```sh
f=$(find target -name bindings.rs -path '*kcapi-sys*' | head -1)
comm -23 \
  <(grep -oE 'pub fn kcapi_[a-z0-9_]+' "$f" | sed 's/pub fn //' | sort -u) \
  <(grep -rhoE 'kcapi_sys::kcapi_[a-z0-9_]+' src/*.rs | sed 's/kcapi_sys:://' | sort -u)
```

The functions still unwrapped are **alternate I/O paths and utilities, not algorithms** — known, intentional follow-ups:

- **AEAD** streaming (`kcapi_aead_stream_*`), AIO (`kcapi_aead_{encrypt,decrypt}_aio`), `kcapi_aead_getdata_{input,output}`, `kcapi_aead_ccm_nonce_to_iv` — would bring `aead` to parity with the streaming/AIO paths `skcipher` already has.
- **akcipher** streaming (`kcapi_akcipher_stream_*`) and AIO (`kcapi_akcipher_*_aio`).
- **KPP** AIO (`kcapi_kpp_keygen_aio`, `kcapi_kpp_ssgen_aio`).
- **Utilities**: `kcapi_set_verbosity`, `kcapi_memset_secure`, `kcapi_versionstring`, `kcapi_handle_reinit`, `kcapi_pad_iv` (note `util::pad_iv`/`util::lib_version` already cover the last two in pure Rust).

When picking one up, mirror the streaming/AIO shape already in `skcipher.rs` (`new_enc_stream`/`stream_update`/`stream_op`, `encrypt_aio`) and gate any test that needs an unavailable kernel feature behind `#[ignore]`.

## Maintenance: versioning, branching, and upgrading libkcapi

### Branching and versioning conventions

- **Commit directly onto `master`.** This project does not use topic branches for maintenance work; infra/version/upgrade commits land straight on `master` in small, focused commits (`scope: Title Case` subject). External contributions still arrive as PRs, but our own crank work does not branch.
- **Version numbers.** `kcapi-sys`'s `major.minor` tracks the vendored libkcapi version (e.g. libkcapi v1.5.0 → `kcapi-sys` 1.5.0); its patch level is for `kcapi-sys`-only changes. `kcapi`'s own version (`0.1.x`) is independent — bump it a step per release. Tag each released version `vX.Y.Z` in its repo.

### Turn-the-crank libkcapi upgrade

Upgrade **one libkcapi version at a time** (iterate if several tags separate current from target), updating `kcapi-sys` then `kcapi`, committing on `master` as you go. Check upstream tags with `git ls-remote --tags --refs https://github.com/smuellerDD/libkcapi.git | sort -V`.

Per version step:

1. **kcapi-sys — point at the new libkcapi.** In `kcapi-sys/`, `git -C libkcapi checkout vX.Y.Z`, then `cargo build`. `build.rs` declares `libkcapi/lib` as a `rerun-if-changed` input, so a normal build regenerates the bindings and relinks after a pointer bump (if you ever suspect stale output, `cargo clean -p kcapi-sys` is a reliable fallback). Confirm the regenerated `bindings.rs` reflects the new API (e.g. `grep -c 'pub fn kcapi_' .../out/bindings.rs`). Commit the `libkcapi` gitlink: *"libkcapi: Update Pointer to vX.Y.Z"*. Run the full gate (build/test/fmt/clippy).
2. **kcapi-sys — bump + tag.** Bump `kcapi-sys/Cargo.toml` to the new version → commit *"Bump up kcapi-sys to Version X.Y.Z"* → `git tag vX.Y.Z`.
3. **kcapi — adopt the new kcapi-sys.** In the parent, bump the `kcapi-sys` gitlink **and** the dependency `version` in `Cargo.toml` together → commit *"kcapi-sys: Update to vX.Y.Z of kcapi-sys"*.
4. **kcapi — wrap any new algorithms.** If the new libkcapi added algorithm convenience functions (verify with the coverage diff above), add safe wrappers + tests in the relevant module → its own commit (e.g. *"md: Add SHA3 digest support"*). Tests for algorithms this build's kernel lacks get `#[ignore]`d.
5. **kcapi — bump + tag.** Bump `kcapi/Cargo.toml` → commit *"Increment Package Minor Version"* → `git tag v0.1.x`. Run the full gate.
6. **Sync + publish.** Fast-forward the standalone `../kcapi-sys` clone to match, then publish to crates.io (`kcapi-sys` first, then `kcapi`) and push. Nothing is pushed/published automatically — that is a deliberate manual step.
