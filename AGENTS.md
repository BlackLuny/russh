# AGENTS.md

## Cursor Cloud specific instructions

`russh` is a Rust (edition 2024) Cargo workspace implementing a low-level Tokio
SSH2 client and server. Crates: `russh` (the library + examples/tests),
`russh-config`, `cryptovec`, `pageant`, `russh-util`.

### Toolchain & dependencies
- The Rust toolchain is pinned by `rust-toolchain.toml` (currently `1.88.0`) and
  is already installed on the VM, along with `clippy` and `rustfmt`.
- The default feature set uses the `aws-lc-rs` crypto backend, which compiles C
  code — `cc`, `gcc`, `cmake`, and `clang` are present on the VM. At least one of
  `aws-lc-rs` or `ring` must be enabled or the `russh` library will not compile.
- The update script runs `cargo fetch` to prime the dependency cache
  (`Cargo.lock` is git-ignored, so dependencies resolve fresh on checkout).

### Build / lint / test / run
Commands mirror `.github/workflows/rust.yml`; consult it as the source of truth.
- Build: `cargo build` and `cargo build --all-features`.
- Lint: `cargo clippy --all-features -- -D warnings` and `cargo fmt --check`.
- Test: run `eval "$(ssh-agent -s)"` first (some tests expect `SSH_AUTH_SOCK`),
  then `cargo test` (and `cargo test --all-features`). Full suite passes
  (300+ tests across the workspace).
- Run a server: `cargo run --example echoserver` starts an SSH server on
  `0.0.0.0:2222` that accepts any public key and echoes channel data. Connect
  with the system `ssh` client or the `client_exec_simple` / `sftp_client`
  examples. See other examples under `russh/examples/`.

### Non-obvious gotchas
- `rustfmt.toml` enables unstable options (`imports_granularity`,
  `group_imports`) that only apply on nightly rustfmt. With the pinned stable
  toolchain, `cargo fmt` prints "unstable features are only available in nightly"
  warnings and does not reorder imports. CI's `Formatting` job runs stable
  rustfmt, so treat stable `cargo fmt --check` as authoritative for what CI sees.
- Several integration tests are gated behind test-only features and are skipped
  by a plain `cargo test`. See `required-features` in `russh/Cargo.toml`
  (`_test_hooks`, `s8_fixture`); `--all-features` builds them.
- A failing `cargo clippy -- -D warnings` or `cargo fmt --check` on an
  in-progress branch usually reflects that branch's own lint/format debt, not a
  broken toolchain — the same commands succeed on `main`.
