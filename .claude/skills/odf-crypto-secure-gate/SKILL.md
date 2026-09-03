---
name: odf-crypto-secure-gate
description: Handling password-derived key material in odf-crypto with secure-gate wrappers. Use when touching derive_key/start_key in decrypt.rs, adding a new KDF or cipher path under the 'decrypt' feature, or wiring the planned encrypt arc's writer-side keys/salts/IVs. Not for the password argument or the returned plaintext Vec<u8> on the public decrypt() API — those stay plain by design — and not for classify/manifest/uris/zip_tree code, which never sees key material.
---

# secure-gate in odf-crypto

**Sole authority for this topic.** No CLAUDE.md or AGENTS.md exists in this repo
yet; this skill is where the policy lives until one does.

## Scope: internal wrapping only — a deliberate choice

odf-crypto is a library, not an app: `decrypt(bytes: &[u8], password: &str) ->
Result<Vec<u8>, DecryptError>` is called by code this repo doesn't control. The
public signature stays plain types on purpose, decided when secure-gate was
adopted here:

- **`password: &str`** — the caller owns it. Wrapping it here adds no
  protection they don't already control, and would force every caller of this
  crate to depend on secure-gate too.
- **The returned `Vec<u8>`** — the entire point of `decrypt()` is handing the
  caller the plaintext ODF zip. Wrapping it internally and unwrapping to
  return would be ceremony with no effect, since the data is about to be
  fully exposed to the caller regardless.

secure-gate wraps only what stays *inside* the crate: the KDF output on its
way from `derive_key` to the cipher constructors in `decrypt_member`.

**Dependency:** `secure-gate = "0.9.0-rc.5"` (`Cargo.toml`), optional, gated
on the `decrypt` feature alongside `zeroize`/`aes`/`argon2`/etc. —
`default-features = false, features = ["alloc"]` only. No `rand`, `ct-eq`, or
`encoding`: this crate never generates a random secret (keys come from a
user-supplied password) and never displays or copies key material anywhere.

## What is wrapped

| Alias | Inner | Declared | Status |
|---|---|---|---|
| `DerivedKey` | `Dynamic<Vec<u8>>` | `src/sensitive.rs`, `pub(crate)` | **Live** — `derive_key`'s return type (`decrypt.rs:177`), consumed in `decrypt_member` (`decrypt.rs:223`). |

That's the whole table today — one alias, one call site. It grows when the
encrypt arc lands (see "Adding a new alias" below).

**Why `Dynamic`, not `Fixed`.** The derived key's length (16/24/32 bytes)
follows `EntryEncryption::derived_key_len`, which tracks whichever AES
variant NSS selected when the file was written — not a compile-time
constant. `Fixed<[u8; N]>` doesn't fit; `Dynamic<Vec<u8>>` does. Contrast
with encrypted-file-vault's `FileKey32` or debitleft's `DbKey32` — both
`Fixed`, because those key sizes are architectural constants the app itself
picked. Reach for `Fixed` when the byte count is fixed by your own design;
reach for `Dynamic` when it's fixed by input you don't control.

## What is deliberately NOT wrapped

- **`password: &str`** and **the returned plaintext `Vec<u8>`** — the public
  API boundary; see "Scope" above.
- **`sk` inside `derive_key`** (the SHA-1/SHA-256 digest of the password —
  the "start key"). It's created and consumed entirely inside `derive_key`
  and never crosses a function boundary, so plain `zeroize::Zeroizing<Vec<u8>>`
  already zeroizes it on every return path, including the early `?` returns.
  This is the rule to internalize: **wrap what crosses a boundary; leave a
  same-function intermediate on bare `Zeroizing` if it already has it.**
  `derived` gets the secure-gate wrapper specifically because it escapes
  `derive_key` into `decrypt_member` — `sk` doesn't escape anywhere.
- **Ciphertext blobs, zip member bytes, manifest XML** — package structure
  and still-encrypted payloads, not credentials.
- **KDF parameters** (`salt`, `iterations`, Argon2 `t`/`m`/`p`) — public, per
  the ODF encryption-data XML; they ship inside the file itself.

## The pattern: wrap at the boundary, not the intermediate

```rust
// decrypt.rs — derive_key: sk stays bare Zeroizing (function-local); derived
// becomes the secure-gate wrapper (it crosses into decrypt_member).
fn derive_key(row: &EntryEncryption, password: &str) -> Result<DerivedKey, DecryptError> {
    let sk = Zeroizing::new(start_key(password, row.start_key));
    let n = row.derived_key_len as usize;
    let mut derived = DerivedKey::new(vec![0u8; n]);
    derived.with_secret_mut(|derived_bytes| -> Result<(), DecryptError> {
        // pbkdf2_hmac(&sk, salt, iterations, derived_bytes) or
        // argon2.hash_password_into(&sk, salt, derived_bytes) write in here
        Ok(())
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
untouched by this — they still take plain `key: &[u8]`. Rust's auto-deref
(`&Vec<u8>` closure parameter coerces to `&[u8]` at the call site) means
neither the KDF calls inside `derive_key` nor the cipher constructors here
needed a signature change to work with the wrapped type's contents. This is
the same reason `pbkdf2_hmac::<Sha1>(&sk, salt, iterations, derived_bytes)`
compiles unchanged from before: `&sk` was already `&Zeroizing<Vec<u8>>`
auto-deref'd to `&[u8]`, and `derived_bytes: &mut Vec<u8>` auto-derefs the
same way.

## Construction

```rust
let derived = DerivedKey::new(vec![0u8; n]);           // used today
```

`DerivedKey::new_with(|v| v.resize(n, 0u8))` is available too, but per
secure-gate's own docs, `Dynamic::new_with` exists "for consistent API idiom,
not for stack-residue avoidance" — unlike `Fixed::new_with`, it buys nothing
here (the heap allocation happens either way), so `new(vec![0u8; n])` is
equally correct and is what the one live call site uses.

## Adding a new alias

`docs/plans/odf-encryption-encrypt-2026-09-03.md` plans a writer-side
`encrypt()`, which will introduce its own key/salt/IV material. Run the same
test before wrapping anything new:

1. **Does it cross a function boundary while still secret?** No → plain
   `Zeroizing`, or nothing at all if it isn't secret (see "What NOT to
   wrap"). Yes → continue.
2. **Is its length fixed by your own design, or by input you don't
   control?** Fixed by design (always exactly N bytes) → `fixed_alias!` in
   `sensitive.rs`. Fixed by input (a manifest field, a negotiated size) →
   `dynamic_alias!`, matching `DerivedKey`.
3. Declare it `pub(crate)` in `sensitive.rs` beside `DerivedKey`, with a doc
   string explaining what it is and — for a `Dynamic` — why not `Fixed`.
4. Check whether the new value needs to leave the crate on a public
   signature. Unlikely per "Scope" above, but a plausible `encrypt()` could
   need to hand back key material for a recovery flow — that's the one case
   that reopens the public-API question. Don't decide it silently; it's the
   same kind of call this skill's "Scope" section made once already for
   `decrypt()`, and it deserves the same explicit treatment, not a default.

## Verify

```bash
cargo build                        # decrypt is a default feature
cargo clippy --all-targets -- -D warnings
cargo test
```

`cargo fmt --all -- --check` already fails on `main`, independent of
secure-gate (confirmed by stashing the secure-gate change and re-running) —
mostly long `format!`/`.ok_or_else` calls an older rustfmt output collapses
differently than the toolchain in this environment does. Check new code on
its own instead of running a blanket reformat that would drag in unrelated
lines: `rustfmt --check --edition 2021 src/<file>.rs`.
