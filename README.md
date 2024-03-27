# 🐒️🥯️

Git signing and verification with OpenPGP cards.

## Setup

```sh
git config --global gpg.program path-to-monkeybagel
```

## Signing

Signing requires that the PIN has been stored using [`openpgp-card-state`][OCS]

[OCS]: https://crates.io/crates/openpgp-card-state

### Basic detached signing

```sh
cargo run -- -bs < Cargo.toml > Cargo.toml.sig
```

## Verification

Verification automatically uses keys stored in CertD.
