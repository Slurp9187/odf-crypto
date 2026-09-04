---
name: odf-crypto-secure-gate
description: Handling password-derived key material and decrypted intermediates in odf-crypto with secure-gate wrappers. Use when touching derive_key/start_key in kdf.rs or the cipher functions in decrypt.rs/encrypt.rs, or adding a new KDF or cipher path under the 'crypto-ops' feature. Not for the password argument or the returned plaintext Vec<u8> on the public decrypt() API — those stay plain by design — and not for classify/manifest/uris/zip_tree code, which never sees key material.
---

# secure-gate in odf-crypto

**Sole authority for this topic.** No CLAUDE.md or AGENTS.md exists in this repo
yet; this skill is where the policy lives until one does.

## The rule: secure-gate is this crate's zeroizing primitive, full stop

odf-crypto used to reach for bare `zeroize::Zeroizing` for anything that
needed zeroizing on drop. It doesn't anymore — **wherever the code used to
zeroize, it now wraps in a secure-gate alias instead**, and every decrypted
intermediate between a cipher and the output zip is wrapped too. There is no
bare `Zeroizing` left anywhere in `src/`, and no "this one's local so plain
`Zeroizing` is enough" exception. Direct `zeroize` is gone from `Cargo.toml` —
secure-gate depends on it internally, so wrapping subsumes it.

**Dependency:** `secure-gate = "0.9.0-rc.7"` (`Cargo.toml`), `default-features
= false, features = ["alloc"]` only — no `rand`, `ct-eq`, or `encoding`. This
crate never generates a random *secret* (keys come from a user-supplied
password; `encrypt`'s salt and IV are public and use `aes-gcm`'s `OsRng`) and
never displays or copies key material anywhere. Unlike
`sha1`/`aes`/`argon2`/etc., **secure-gate is not optional and not gated on the
`crypto-ops` feature** — it's an unconditional dependency, even though today
only the `crypto-ops`-gated `sensitive.rs` / `decrypt.rs` / `encrypt.rs` /
`kdf.rs` use it. The other deps in the `crypto-ops` feature list are swappable
algorithm implementations a `classify`-only consumer has no reason to pull in;
secure-gate is infrastructure, not an algorithm choice.

`decrypt` and `encrypt` were separate features until they were collapsed into
`crypto-ops`: they pulled an identical dependency graph, and the split's only
product was a third build configuration for a mis-scoped `cfg` to hide in.

## Scope: the public API stays plain

odf-crypto is a library, not an app: `decrypt(bytes: &[u8], password: &str) ->
Result<Vec<u8>, DecryptError>` is called by code this repo doesn't control.
The public signature stays plain types on purpose:

- **`password: &str`** — the caller owns it. Wrapping it here adds no
  protection they don't already control, and would force every caller of this
  crate to depend on secure-gate too.
- **The returned `Vec<u8>`** — the entire point of `decrypt()` is handing the
  caller the plaintext ODF zip. It is built by the zip writer from wrapped
  members and leaves the crate as a plain `Vec<u8>`; wrapping it would be
  ceremony with no effect, since the caller receives it in full regardless.

Everything *between* those two ends is wrapped: the password digest, the
derived key, each decrypted member in both its deflated and inflated forms.

## What is wrapped

| Alias | Inner | Declared | Status |
|---|---|---|---|
| `PasswordDigest` | `Dynamic<Vec<u8>>` | `src/sensitive.rs`, `pub(crate)` | **Live** — `start_key`'s return type (`kdf.rs:38`), written in place by `finalize_into` (`kdf.rs:44`), consumed by `derive_key` (`decrypt.rs:200`). |
| `DerivedKey` | `Dynamic<Vec<u8>>` | `src/sensitive.rs`, `pub(crate)` | **Live** — `derive_key`'s return type (`decrypt.rs:200`), consumed in `decrypt_member` (`:244`). Also `encrypt`'s wholesome key (`encrypt.rs:181`). |
| `DeflatedPlaintext` | `Dynamic<Vec<u8>>` | `src/sensitive.rs`, `pub(crate)` | **Live** — returned by `decrypt_aes_gcm` (`:252`), `decrypt_aes_cbc` (`:290`), `decrypt_blowfish_cfb64` (`:335`) and `decrypt_member` (`:239`); inflated inside `with_secret` (`:109` wholesome, `:124` per-entry). Also `encrypt`'s deflated-then-sealed payload (`encrypt.rs:169`). |
| `MemberPlaintext` | `Dynamic<Vec<u8>>` | `src/sensitive.rs`, `pub(crate)` | **Live** — the values of the `plain` map in `decrypt` (`:112`); `rebuild_zip` (`:476`) writes each straight from the wrapper into the zip writer (`:514`). |

All four are `Dynamic<Vec<u8>>`, not `Fixed<[u8; N]>`. **Why `Dynamic`.**
`PasswordDigest` is 20 bytes for SHA-1 or 32 for SHA-256, decided by
`StartKeyAlg`; `DerivedKey`'s length (16/24/32) follows
`EntryEncryption::derived_key_len`; the two plaintext aliases are whatever
size the member is. None is a compile-time constant. Contrast with
encrypted-file-vault's `FileKey32` or debitleft's `DbKey32` — both `Fixed`,
because those key sizes are architectural constants the app itself picked.
Reach for `Fixed` when the byte count is fixed by your own design; reach for
`Dynamic` when it's fixed by input you don't control.

## What is deliberately NOT wrapped

- **`password: &str`** and **the returned zip `Vec<u8>`** — the public API
  boundary; see "Scope" above.
- **Ciphertext blobs, zip member bytes, manifest XML** — package structure
  and still-encrypted payloads, not credentials. `rebuild_zip` still reads
  every member into a plain `body` buffer; for encrypted members that buffer
  is ciphertext and gets replaced, never decrypted in place.
- **KDF parameters** (`salt`, `iterations`, Argon2 `t`/`m`/`p`) — public, per
  the ODF encryption-data XML; they ship inside the file itself.

## Residual the wrapper cannot reach — know it, don't chase it

`start_key` writes the digest straight into the wrapper's heap buffer via
`finalize_into` (see "Construction"), so no stack copy of the *digest*
survives. Two things still do, and neither can be fixed from this crate:

- The `Sha1`/`Sha256` hasher buffers the raw password bytes internally until
  `finalize` (`BlockBuffer::reset` only zeroes the position, not the bytes),
  and is dropped unzeroized.
- `sha1::compress` / `sha2::compress256` spill their message schedule on the
  stack — and `W[0..16]` of that schedule *is* the message block verbatim.

`digest`/`sha1`/`sha2` at 0.10 expose no `zeroize` feature (checked: zero
references in all three `Cargo.toml`s). Hand-rolling the hash over the public
`compress` function would remove the first copy and leave the second, i.e. buy
nothing an attacker reading the stack would notice. The fix is upstream — a
hasher that zeroizes its state *and* its schedule — and in practice the KDF
that runs next (`pbkdf2_hmac` / Argon2) overwrites that stack region within
microseconds. Don't reimplement SHA here to close it.

## Guards that sit next to the wrapping

`DERIVED_KEY_MIN_LEN = 1` / `DERIVED_KEY_MAX_LEN = 64` (`limits.rs:50-51`,
inside the `crypto-ops`-gated `crypto` submodule) bound `manifest:key-size`
*before* `derive_key` allocates the key buffer (`decrypt.rs:203`). `derived_key_len` is
an `i32` the manifest controls; without the bound a value near `i32::MAX`
allocates ~2 GiB and then runs PBKDF2 over all of it — a hang no `Result` can
report — before any cipher gets to reject the length. AES-256 needs 32 and
Blowfish accepts at most 56, so 64 rejects nothing LibreOffice would open.
`hostile_derived_key_len_is_refused_before_allocating` (`decrypt_tests.rs`)
checks that `classify` passes the hostile value through unchanged, so the
guard — not the parser — is what the test exercises.

## The pattern

```rust
// kdf.rs — start_key: the digest lands in the wrapper's own buffer. Shared
// with encrypt since #24; decrypt.rs calls crate::kdf::start_key.
fn start_key(password: &str, alg: StartKeyAlg) -> PasswordDigest {
    fn digest_into<D: Digest>(password: &str) -> PasswordDigest {
        let mut h = D::new();
        h.update(password.as_bytes());
        PasswordDigest::new_with(|v| {
            v.resize(<D as Digest>::output_size(), 0);
            h.finalize_into(Output::<D>::from_mut_slice(v));
        })
    }
    match alg {
        StartKeyAlg::Sha1 => digest_into::<Sha1>(password),
        StartKeyAlg::Sha256 => digest_into::<Sha256>(password),
    }
}

// derive_key: sk read, derived written, in one nested scope.
fn derive_key(row: &EntryEncryption, password: &str) -> Result<DerivedKey, DecryptError> {
    let sk = start_key(password, row.start_key);
    let n = row.derived_key_len;
    if !(DERIVED_KEY_MIN_LEN..=DERIVED_KEY_MAX_LEN).contains(&n) { /* BadParameters, no allocation */ }
    let mut derived = DerivedKey::new(vec![0u8; n as usize]);
    sk.with_secret(|sk_bytes| {
        derived.with_secret_mut(|derived_bytes| -> Result<(), DecryptError> {
            // pbkdf2_hmac(sk_bytes, salt, iterations, derived_bytes) or
            // argon2.hash_password_into(sk_bytes, salt, derived_bytes)
            Ok(())
        })
    })?;
    Ok(derived)
}

// decrypt_member: the whole cipher dispatch inside the closure; every cipher
// returns DeflatedPlaintext, so key bytes and plaintext never meet unwrapped.
fn decrypt_member(row: &EntryEncryption, password: &str, blob: &[u8])
    -> Result<DeflatedPlaintext, DecryptError>
{
    let key = derive_key(row, password)?;
    key.with_secret(|k| match row.cipher {
        Cipher::AesGcmW3c => decrypt_aes_gcm(k, row, blob),
        Cipher::AesCbcW3c => decrypt_aes_cbc(k, row, blob),
        Cipher::BlowfishCfb8 => decrypt_blowfish_cfb64(k, row, blob),
    })
}

// decrypt: inflate inside with_secret; the wholesome path returns the inflated
// package directly (that IS the public return), the per-entry path wraps each
// member until rebuild_zip writes it.
let inflated = compressed.with_secret(|c| raw_inflate(c, row.size))?;
plain.insert(member, MemberPlaintext::new(inflated));
// ... in rebuild_zip:
pt.with_secret(|p| out.write_all(p))?;
```

Three shapes worth naming:

- **In-place ciphers wrap before the first block turns into plaintext.**
  `decrypt_aes_cbc` and `decrypt_blowfish_cfb64` do
  `DeflatedPlaintext::new(blob.to_vec())` first, then decrypt inside
  `with_secret_mut`. The CBC padding strip is a `truncate` inside that same
  closure — the stripped bytes land in spare capacity, which the wrapper
  zeroizes too.
- **Producing ciphers move, they don't copy.** AES-GCM's `aead` decrypt hands
  back a fresh `Vec`; `.map(DeflatedPlaintext::new)` moves it into the wrapper
  with no byte copy.
- **Writers write from the wrapper.** `rebuild_zip` used to `pt.clone()` each
  member into a plain `body` then `write_all(&body)`; now it does
  `pt.with_secret(|p| out.write_all(p))` — no unwrapped clone of any plaintext
  along the way.

`pbkdf2_hmac`, `hash_password_into`, the cipher constructors and `raw_inflate`
all still take plain `&[u8]`/`&mut [u8]`. Rust's auto-deref (`&Vec<u8>` /
`&mut Vec<u8>` closure parameters coerce at the call site) means none of them
needed a signature change.

## Construction

```rust
PasswordDigest::new_with(|v| { v.resize(N, 0); h.finalize_into(Output::<D>::from_mut_slice(v)); })
DerivedKey::new(vec![0u8; n])
DeflatedPlaintext::new(blob.to_vec())      // in-place ciphers, before decrypting
out.map(DeflatedPlaintext::new)            // producing ciphers, a move
MemberPlaintext::new(inflated)             // a move
```

Per secure-gate's own docs, `Dynamic::new_with` exists "for consistent API
idiom, not for stack-residue avoidance" — the wrapper's allocation is heap
either way. It earns its keep in `start_key` for a different reason: it gives
`finalize_into` a buffer to write *into*, so the digest never exists as a
returned `GenericArray` on the stack (which `finalize().to_vec()` would
produce). Where there is no such writer, `new(...)` is equally correct and is
what the other call sites use. The rule for a new alias: **the function that
creates sensitive material hands back the wrapper** — `start_key`,
`derive_key` and every cipher fn do — rather than a bare value the caller has
to remember to wrap.

## Adding a new alias

`docs/plans/odf-encryption-encrypt-2026-09-03.md`'s writer-side `encrypt()`
landed in #24 and needed **no new alias**: key derivation is shared through
`kdf.rs`, so it reuses `PasswordDigest` and `DerivedKey` verbatim, and its
deflated-then-sealed buffer is `DeflatedPlaintext` travelling the other way
(wrapped before the cipher runs, written to the zip straight from the wrapper).
Its salt and IV are deliberately *not* wrapped: both are written to the
manifest in the clear, so they are public by construction, like the KDF
parameters beside them. For the next arc that does introduce new material,
apply the same rule: if it is key material or plaintext living inside this crate, it's a
secure-gate alias, regardless of whether it crosses a function boundary.

1. **Is its length fixed by your own design, or by input you don't
   control?** Fixed by design (always exactly N bytes) → `fixed_alias!` in
   `sensitive.rs`. Fixed by input (a manifest field, a member's size) →
   `dynamic_alias!`, matching the four aliases already there.
2. Declare it `pub(crate)` in `sensitive.rs` beside its peers, with a doc
   string explaining what it is and — for a `Dynamic` — why not `Fixed`.
3. Wrap at the point of creation, in the function that produces the value
   (`start_key`, the cipher fns). If a library can write into a buffer you
   supply, hand it the wrapper's buffer via `new_with`, as `finalize_into`
   does.
4. Check whether the new value needs to leave the crate on a public
   signature. Unlikely per "Scope" above, but a plausible `encrypt()` could
   need to hand back key material for a recovery flow — that's the one case
   that reopens the public-API question. Don't decide it silently; it's the
   same kind of call this skill's "Scope" section made once already for
   `decrypt()`, and it deserves the same explicit treatment, not a default.

## Verify

Detection is the default build now, so the cryptographic paths need naming
explicitly:

```bash
cargo build --no-default-features                     # secure-gate compiles either way
cargo build --no-default-features --features crypto-ops
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --no-default-features --features crypto-ops -- -D warnings
cargo test  --no-default-features --features crypto-ops   # 107 tests, every golden KDF/cipher path
cargo fmt --all --check
```

`cargo fmt --all --check` used to fail on `main` independently of secure-gate.
It no longer does — the drift was cleared, so a failure now is yours.
