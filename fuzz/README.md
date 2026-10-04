# Security fuzzing

The targets exercise the production Rust library without running a server or
reading personal vaults. Cargo's `fuzzing` feature exposes parser-only helpers;
normal builds do not include those helpers.

Clone the source repository before running these commands; release archives
contain this guide but not the developer fuzz harness.

Use a native C/C++ build toolchain, install nightly Rust and `cargo-fuzz`, then
run from the repository root:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked
mkdir -p fuzz/corpus/encrypted_headers fuzz/corpus/native_messages fuzz/corpus/imports
cp fuzz/seeds/encrypted_headers/* fuzz/corpus/encrypted_headers/
cp fuzz/seeds/native_messages/* fuzz/corpus/native_messages/
cp fuzz/seeds/imports/* fuzz/corpus/imports/
cargo +nightly fuzz run encrypted_headers -- -max_total_time=600 -max_len=65536
cargo +nightly fuzz run native_messages -- -max_total_time=600 -max_len=65536
cargo +nightly fuzz run imports -- -max_total_time=600 -max_len=65536
```

- `encrypted_headers` validates arbitrary headers and decrypts using cached
  synthetic keys. It also encrypts each input, checks its round trip, and rejects
  a mutated ciphertext or authenticated header. It never runs Argon2 against
  attacker-chosen parameters, so KDF resource-limit tests remain in the Rust suite.
- `native_messages` parses native-message framing, validates JSON requests into
  commands without delivering them, and parses MessagePack commands and response
  frames. Inputs contain no live authentication material.
- `imports` runs the CSV and portable JSON parsers on UTF-8 inputs and drops their
  secret-bearing records after parsing.

The security-fuzz workflow runs bounded checks on relevant pull requests and
longer weekly or manually triggered sessions (60 seconds per target on pull
requests and 600 seconds otherwise). It caches discovered corpus entries per
target and uploads crash artifacts on failure. Fuzzer findings fail CI; timeout completion is normal.
Sanitizers and coverage instrumentation require nightly Rust. Stable builds can
run a basic parser smoke check without coverage guidance:

```bash
cargo run --manifest-path fuzz/Cargo.toml --locked --bin imports -- fuzz/seeds/imports -runs=200
```

Use only synthetic credentials. Do not commit discovered corpus entries or crash
artifacts without checking that they contain no real secrets. Runtime corpora,
artifacts, and build outputs are ignored by Git. Reproduce a finding with:

```bash
cargo +nightly fuzz run imports fuzz/artifacts/imports/crash-EXAMPLE
```

Minimize the input, fix the parser, and add a focused regression test before
promoting a sanitized input into the tracked `fuzz/seeds` directory.

The harness uses [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) and libFuzzer.
