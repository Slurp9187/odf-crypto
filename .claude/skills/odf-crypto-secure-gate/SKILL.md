---
name: odf-crypto-secure-gate
description: Handling password-derived key material in odf-crypto with secure-gate wrappers. Use when touching derive_key/start_key in decrypt.rs, adding a new KDF or cipher path under the 'decrypt' feature, or wiring the planned encrypt arc's writer-side keys/salts/IVs. Not for the password argument or the returned plaintext Vec<u8> on the public decrypt() API — those stay plain by design — and not for classify/manifest/uris/zip_tree code, which never sees key material.
---

# secure-gate in odf-crypto

**Sole authority for this topic.** No CLAUDE.md or AGENTS.md exists in this repo
yet; this skill is where the policy lives until one does.

## The rule: secure-gate is this crate's zeroizing primitive, full stop

odf-crypto used to reach for bare `zeroize::Zeroizing` for anything that
needed zeroizing on drop. It doesn't anymore — **wherever the code used to
zeroize, it now wraps in a secure-gate alias instead.** There is no bare
`Zeroizing` left anywhere in `src/`, and there is no "this one's local so
plain `Zeroizing` is enough" exception: both values in `derive_key` (the
password digest and the derived cipher key) are wrapped, not just the one
that crosses a function boundary. Direct `zeroize` is gone from `Cargo.toml`
— secure-gate depends on it internally, so wrapping subsumes it rather than
sitting alongside it.

**Dependency:** `secure-gate = "0.9.0-rc.7"` (`Cargo.toml`), `default-features
= false, features = ["alloc"]` only — no `rand`, `ct-eq`, or `encoding`, since
this crate never generates a random secret (keys come from a user-supplied
password) and never displays or copies key material anywhere. Unlike
`sha1`/`aes`/`argon2`/etc., **secure-gate is not optional and not gated on the
`decrypt` feature** — it's an unconditional dependency of the crate, even
though today only the `decrypt`-gated `sensitive.rs`/`decrypt.rs` actually use
it. That's a deliberate choice: the other deps in the `decrypt` feature list
are swappable algorithm implementations a `classify`-only consumer has no
reason to pull in; secure-gate is infrastructure, not an algorithm choice.

## Scope: internal wrapping only — the public API stays plain

odf-crypto is a library, not an app: `decrypt(bytes: &[u8], password: &str) ->
Result<Vec<u8>, DecryptError>` is called by code this repo doesn't control.
The public signature stays plain types on purpose:

- **`password: &str`** — the caller owns it. Wrapping it here adds no
  protection they don't already control, and would force every caller of this
  crate to depend on secure-gate too.
- **The returned `Vec<u8>`** — the entire point of `decrypt()` is handing the
  caller the plaintext ODF zip. Wrapping it internally and unwrapping to
  return would be ceremony with no effect, since the data is about to be
  fully exposed to the caller regardless.

This is a different axis from the zeroizing rule above: "wrap everywhere
zeroizing happens" governs *internal* key material; the public API boundary
is governed by "don't force a wrapper dependency on callers for values they
already own or are about to receive in full." Both are real rules; they
don't conflict because nothing on the public signature was ever a zeroizing
candidate — a `&str` the caller owns isn't this crate's to zeroize, and the
returned plaintext isn't secret key material.

## What is wrapped

| Alias | Inner | Declared | Status |
|---|---|---|---|
| `PasswordDigest` | `Dynamic<Vec<u8>>` | `src/sensitive.rs`, `pub(crate)` | **Live** — `start_key`'s return type (`decrypt.rs:161`), consumed by `derive_key` (`decrypt.rs:177`). |
| `DerivedKey` | `Dynamic<Vec<u8>>` | `src/sensitive.rs`, `pub(crate)` | **Live** — `derive_key`'s return type (`decrypt.rs:176`), consumed in `decrypt_member` (`decrypt.rs:219`). |

Both are `Dynamic<Vec<u8>>`, not `Fixed<[u8; N]>`. **Why `Dynamic`.**
`PasswordDigest` is 20 bytes for SHA-1 or 32 for SHA-256, decided by
`StartKeyAlg`; `DerivedKey`'s length (16/24/32 bytes) follows
`EntryEncryption::derived_key_len`, tracking whichever AES variant NSS
selected when the file was written. Neither is a compile-time constant.
Contrast with encrypted-file-vault's `FileKey32` or debitleft's `DbKey32` —
both `Fixed`, because those key sizes are architectural constants the app
itself picked. Reach for `Fixed` when the byte count is fixed by your own
design; reach for `Dynamic` when it's fixed by input you don't control.

## What is deliberately NOT wrapped

- **`password: &str`** and **the returned plaintext `Vec<u8>`** — the public
  API boundary; see "Scope" above. Neither one is this crate's zeroizing
  responsibility.
- **Ciphertext blobs, zip member bytes, manifest XML** — package structure
  and still-encrypted payloads, not credentials, and never zeroized before
  this change either.
- **KDF parameters** (`salt`, `iterations`, Argon2 `t`/`m`/`p`) — public, per
  the ODF encryption-data XML; they ship inside the file itself.

## The pattern: everything zeroize used to cover, now secure-gate

```rust
// decrypt.rs — start_key returns the wrapped digest directly; derive_key
// wraps the KDF output the same way. Both closures nest because the KDF
// call needs read access to sk and write access to derived at once.
fn start_key(password: &str, alg: StartKeyAlg) -> PasswordDigest {
    match alg {
        StartKeyAlg::Sha1 => {
            let mut h = Sha1::new();
            h.update(password.as_bytes());
            PasswordDigest::new(h.finalize().to_vec())
        }
        StartKeyAlg::Sha256 => { /* same shape, Sha256 */ }
    }
}

fn derive_key(row: &EntryEncryption, password: &str) -> Result<DerivedKey, DecryptError> {
    let sk = start_key(password, row.start_key);
    let n = row.derived_key_len as usize;
    let mut derived = DerivedKey::new(vec![0u8; n]);
    sk.with_secret(|sk_bytes| {
        derived.with_secret_mut(|derived_bytes| -> Result<(), DecryptError> {
            // pbkdf2_hmac(sk_bytes, salt, iterations, derived_bytes) or
            // argon2.hash_password_into(sk_bytes, salt, derived_bytes) write in here
            Ok(())
        })
    })?;
    Ok(derived)
}

// decrypt_member — Tier 1 with_secret: the whole cipher dispatch happens
// inside the closure, key bytes never escape it.
fn decrypt_member(row: &EntryEncryption, password: &str, blob: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let key = derive_key(row, password)?;
    key.with_secret(|k| match row.cipher {
        Cipher::AesGcmW3c => decrypt_aes_gcm(k, row, blob),
        Cipher::AesCbcW3c => decrypt_aes_cbc(k, row, blob),
        Cipher::BlowfishCfb8 => decrypt_blowfish_cfb64(k, row, blob),
    })
}
```

`decrypt_aes_gcm`, `decrypt_aes_cbc`, and `decrypt_blowfish_cfb64` are
untouched by this — they still take plain `key: &[u8]`, and `pbkdf2_hmac`/
`argon2.hash_password_into` still take plain `&[u8]`/`&mut [u8]` too. Rust's
auto-deref (`&Vec<u8>` and `&mut Vec<u8>` closure parameters coerce to
`&[u8]`/`&mut [u8]` at the call site) means none of those signatures needed
to change to work with the wrapped types' contents — only `start_key` and
`derive_key` themselves, which now return the wrapper instead of a bare
`Vec<u8>`/`Zeroizing<Vec<u8>>`.

## Construction

```rust
PasswordDigest::new(h.finalize().to_vec())   // start_key — wrap at creation
DerivedKey::new(vec![0u8; n])                // derive_key — used today
```

`DerivedKey::new_with(|v| v.resize(n, 0u8))` is available too, but per
secure-gate's own docs, `Dynamic::new_with` exists "for consistent API idiom,
not for stack-residue avoidance" — unlike `Fixed::new_with`, it buys nothing
here (the heap allocation happens either way), so `new(vec![0u8; n])` is
equally correct and is what the live call site uses. `start_key` wraps at
the point of creation (inside the function that produces the digest) rather
than at the call site in `derive_key` — prefer that shape for a new alias
too: the function that creates sensitive material should hand back the
wrapped type directly, not a bare value the caller has to remember to wrap.

## Adding a new alias

`docs/plans/odf-encryption-encrypt-2026-09-03.md` plans a writer-side
`encrypt()`, which will introduce its own key/salt/IV material. Apply the
same rule: if it would have been `zeroize::Zeroizing` before, it's a
secure-gate alias now, regardless of whether it crosses a function boundary.

1. **Is its length fixed by your own design, or by input you don't
   control?** Fixed by design (always exactly N bytes) → `fixed_alias!` in
   `sensitive.rs`. Fixed by input (a manifest field, a negotiated size) →
   `dynamic_alias!`, matching `PasswordDigest`/`DerivedKey`.
2. Declare it `pub(crate)` in `sensitive.rs` beside the existing two, with a
   doc string explaining what it is and — for a `Dynamic` — why not `Fixed`.
3. Wrap at the point of creation, not the point of first use, when the
   creating function is itself private to this crate — see `start_key` above.
4. Check whether the new value needs to leave the crate on a public
   signature. Unlikely per "Scope" above, but a plausible `encrypt()` could
   need to hand back key material for a recovery flow — that's the one case
   that reopens the public-API question. Don't decide it silently; it's the
   same kind of call this skill's "Scope" section made once already for
   `decrypt()`, and it deserves the same explicit treatment, not a default.

## Verify

```bash
cargo build                        # decrypt is a default feature
cargo build --no-default-features  # secure-gate compiles in either way
cargo clippy --all-targets -- -D warnings
cargo test
```

`cargo fmt --all -- --check` already fails on `main`, independent of
secure-gate (confirmed by stashing the secure-gate change and re-running) —
mostly long `format!`/`.ok_or_else` calls an older rustfmt output collapses
differently than the toolchain in this environment does. Check new code on
its own instead of running a blanket reformat that would drag in unrelated
lines: `rustfmt --check --edition 2021 src/<file>.rs`.
