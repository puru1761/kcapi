# KCAPI - The Official High-level Rust Bindings for libkcapi

![CI Badge](https://github.com/puru1761/kcapi/actions/workflows/main.yml/badge.svg)

This repository contains the rust sources for the official high-level rust
bindings for `libkcapi` - A userspace interface to the Linux Kernel's
Cryptographic API (KCAPI). These bindings are based on top of the `kcapi-sys`
crate which is a submodule of this crate.

## Usage

In order to include this crate in your dependencies, include it in your
Cargo.toml as follows:

```
kcapi = "0.1.0"
```

Once this is done, you may access the various modules provided by this
crate in your Rust sources:

The major modules provided by this crate are:

* `kcapi::md` - Provides message digest capabilities
* `kcapi::skcipher` - Provides symmetric key ciphers
* `kcapi::aead` - Provides Authenticated Encryption with Associated Data (AEAD) Ciphers
* `kcapi::rng` - Provides Random Number Generation support.
* `kcapi::akcipher` - Provides Asymmetric key ciphers.

A simple example for using the convenience hash API is given below:

```rust
fn main() {
    let input = "This is a test string to be hashed!".as_bytes().to_vec();
    let digest = match kcapi::md::digest(
        "sha1"  // The algorithm to be used for the digest (from /proc/crypto)
        input,  // The input to be digested
        0,      // The flags to set for cipher operation (Symmetric or AIO)
    ) {
        Ok(digest) => digest,
        Err(e) => panic!("{}", e),
    }

    println!("{}", hex::encode(digest));
}
```

Each API provided will return a `KcapiResult` typed `Result` enum. On error, a
`KcapiError` will be returned which has the following structure:

```rust
struct KcapiError {
    code: i64,          // The Error code (generally errno style)
    message: String     // The error message which can be printed
}
```

## Build and Test

This section describes how the `kcapi` crate can be built and tested locally.

### Pre-requisites

In order to build this project, it must be checked out along with all of it's
submodules recursively:

```
git clone https://github.com/puru1761/kcapi.git --recurse-submodules
```

Install all build dependencies. These are:

* `autotools`
* `autoconf`
* `llvm-dev`

#### RPM based packages

```
sudo yum install automake autoconf llvm-devel
```

#### Debian based packages

```
sudo apt-get install autotools-dev autoconf llvm-dev
```

If `LLVM_CONFIG_PATH` is not set, then set it with:

```
export LLVM_CONFIG_PATH="/path/to/llvm-config"
```

### Build

We use cargo as our build system for building this crate. Build it using:

```
cargo build
```

### Test

We have a few sanity tests written to make sure that the bindings work
as expected. Run these tests using:

```
cargo test
```

All of these tests are defined in `src/test/test_*.rs`. Developers are welcome
to write more tests here in order to ensure that our code quality is the best.

## Author

* Purushottam A. Kulkarni <<puruk@protonmail.com>>