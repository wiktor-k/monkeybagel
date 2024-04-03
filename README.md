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
monkeybagel -u SIGNING_KEY_FPR --detach-sign < Cargo.toml > Cargo.toml.sig
```

The `SIGNING_KEY_FPR` parameter must be set to the fingerprint of the *signing* subkey (not the certificate) in a hex-encoded format with *no* spaces (`0x` prefix is optional and removed during comparisons).

The fingerprint may be retrieved using `oct status` command.

## Verification

Verification automatically uses keys stored in CertD:

```sh
monkeybagel --verify Cargo.toml.sig - < Cargo.toml
```
