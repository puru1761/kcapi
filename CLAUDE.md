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
