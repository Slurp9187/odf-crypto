---
name: odf-crypto-secure-gate
description: Handling password-derived key material and decrypted intermediates in odf-crypto with secure-gate wrappers. Use when touching start_key/derive_key or the cipher functions in decrypt.rs/encrypt.rs, adding a KDF or cipher path, or adding an alias to sensitive.rs. Not for the password argument or the returned plaintext Vec<u8> on the public decrypt() API — those stay plain by design — and not for classify/manifest/uris/zip_tree code, which never sees key material.
---

# secure-gate in odf-crypto

**Sole authority for this topic.** `CLAUDE.md` carries the project rules and points here for
secret handling; if the two ever disagree about secure-gate, this file is right.

The protocol — access tiers, the residue hazards, Fixed vs Dynamic, alias vs newtype, the
reveal-borrow defect, the pin argument — is in the global `secure-gate` skill. **This file
records only what is true of this crate.**

> **No line numbers in this file, deliberately.** The citations that used to be here drifted
> three times, were repaired three times, and the previous revision wrote down what to do if it
> happened a fourth: *replace the line numbers with function names and let `grep` do the work.*
> It happened a fourth time — the known-unfixed realloc site moved from `encrypt.rs:204` to
> `:621`. Function names it is. They have been stable since the decrypt arc; every line number
> has moved at least once.

## Dependency

```toml
secure-gate = { version = "=0.9.0-rc.12", default-features = false, features = ["alloc"] }
```

`alloc` only — **no `rand`, no `ct-eq`, no `encoding`.** This crate never generates a random
*secret* (keys come from a user-supplied password; `encrypt`'s salt and IV are public and use
`aes-gcm`'s RNG) and never displays or copies key material. Confirmed by measurement: zero call
sites for `from_random`, `from_rng` or `ct_eq`.

**Unconditional — not gated on `crypto-ops`**, unlike `sha1`/`aes`/`argon2` and the rest. Those
are swappable algorithm implementations a `classify`-only consumer has no reason to pull in;
secure-gate is infrastructure, not an algorithm choice. Direct `zeroize` is gone from
`Cargo.toml` — secure-gate depends on it internally, so wrapping subsumes it.

**There is no bare `Zeroizing` left anywhere in `src/`**, and no "this one's local so plain is
enough" exception.

**Every rule in the global skill is read against rc.12.** This crate declares no newtypes, so
the rc.13 `derive: [ConstantTimeEq]` break does **not** hit it — but the bump is still a
coordinated ecosystem wave, since four first-party crates pin exactly. See the global skill's
*upgrade* reference.

## Boundary — the public API stays plain

`decrypt(bytes: &[u8], password: &str) -> Result<Vec<u8>, DecryptError>` is called by code this
repo does not control. The caller owns the password, and handing back the plaintext ODF zip
*is* the function. Everything *between* those ends is wrapped.

The one case that would reopen it: a plausible `encrypt()` recovery flow needing to hand back
key material. Do not decide that silently — it deserves the same explicit treatment `decrypt()`
already got.

## The four aliases

All in `src/sensitive.rs`, all `pub(crate)`, all plain `type` aliases over `Dynamic<Vec<u8>>`.

| Alias | Holds | Produced by |
|---|---|---|
| `PasswordDigest` | SHA-1 (20 B) or SHA-256 (32 B) of the password, per `StartKeyAlg` | `start_key`, written in place by `finalize_into` |
| `DerivedKey` | the PBKDF2/Argon2 output, length from `derived_key_len` (16/24/32) | `derive_key` |
| `DeflatedPlaintext` | a member's decrypted-but-still-compressed bytes | the three cipher fns; also `encrypt`'s deflated payload |
| `MemberPlaintext` | a member's inflated plaintext | built by `try_new_with` so the inflate writes into the wrapper |

**`Dynamic`, not `Fixed`:** none of these lengths is a compile-time constant. The digest
follows the hash the file names; the derived key follows a manifest field; the two plaintext
aliases are whatever size the member is. Contrast a consuming application's own file key, which
is `Fixed` because its byte count is an architectural constant that application chose.

**All four are the same nominal type** and are freely substitutable — passing a digest where a
derived key is expected compiles. The aliases buy a greppable name and zeroize-on-drop, **not
type safety**. That limitation is stated in `sensitive.rs` too, because it is exactly what
upstream deleted the alias macros over.

## Tier 1 only

Measured in `src/` (files, not occurrences):

```sh
for m in with_secret with_secret_mut expose_secret into_inner new_with try_new_with ct_eq from_rng; do
  printf '%-16s %s\n' "$m" "$(grep -rl "$m" --include=*.rs src/ | wc -l)"
done
```

| method | files |
|---|---|
| `with_secret` | 3 |
| `with_secret_mut` | 3 |
| `new_with` | 3 |
| `try_new_with` | 2 |
| `expose_secret` | **0** |
| `into_inner` | **0** |
| `ct_eq` / `from_rng` / `from_random` | **0** |

**No Tier 2 and no Tier 3.** Keep it that way — the first `expose_secret` is a decision to
argue for, not a convenience.

⚠️ **Grep trap:** a bare `grep into_inner` returns hits in 3 files. Every one is
`ZipWriter::finish()` feeding `Cursor::into_inner()`, in `decrypt.rs`, `encrypt.rs` and
`test_support.rs`. Confirm that is still true rather than assuming it — and note that
`into_inner` changed meaning silently at rc.9, so a real secure-gate hit here would matter.

## Construction — the producer decides

```rust
PasswordDigest::new_with(N, |slot| ...)          // finalize_into writes into the slot
MemberPlaintext::try_new_with(n, |slot| ...)     // the inflate writes into the wrapper
DerivedKey::new(vec![0u8; n])                    // sized up front, filled via with_secret_mut
DeflatedPlaintext::new(blob.to_vec())            // in-place ciphers, wrapped before decrypting
out.map(DeflatedPlaintext::new)                  // producing ciphers — a move, not a copy
```

**Do not convert the remaining `new(...)` sites to `new_with(...)`.** An owned return means
`new` is already a move, and `new_with` would wrap a closure around a copy from a source that
stays unprotected — strictly worse. The inflate went the other way only because the *producer*
changed: miniz_oxide can write into a caller slice, so there is no longer an owned `Vec` to
move. **The question is always what the producer does, never which constructor reads better.**

### The one realloc hazard this crate still has

`DeflatedPlaintext::new(raw_deflate(bytes)?)` in `encrypt.rs` wraps a buffer
`miniz_oxide::deflate::compress_to_vec` **grew**. Deflate has no declared output length to size
a slot from — that is what `manifest:size` gives the decrypt direction and nothing gives this
one — so closing it needs an upper bound and a truncate, not a slot. **Left as is rather than
papered over.**

## Guards that sit next to the wrapping

`DERIVED_KEY_MIN_LEN = 1` / `DERIVED_KEY_MAX_LEN = 64` in `limits.rs` bound `manifest:key-size`
*before* `derive_key` allocates. `derived_key_len` is an `i32` the manifest controls; without
the bound a value near `i32::MAX` allocates ~2 GiB and then runs PBKDF2 over all of it — a hang
no `Result` can report. AES-256 needs 32 and Blowfish accepts at most 56, so 64 rejects nothing
LibreOffice would open.

`inflated_len` is the same shape for `manifest:size`, and it exists *because* the inflate moved
into a sized slot: `size` is now an allocation length, not a value checked afterwards.

Three tests pin these, all verified by breaking what they guard:
`hostile_derived_key_len_is_refused_before_allocating`,
`hostile_manifest_size_is_refused_before_allocating`, and
`overstated_manifest_size_is_rejected_rather_than_zero_padded` — the subtle one, since a slot is
zero-filled, so an overstated `size` inflates short and the decoder still reports success,
leaving a tail of zeros that only the written-vs-slot-length comparison catches.

## Deliberately not wrapped

- **`password: &str` and the returned zip `Vec<u8>`** — the public boundary.
- **Ciphertext blobs, zip member bytes, manifest XML** — package structure and still-encrypted
  payloads. `rebuild_zip` reads every member into a plain buffer; for encrypted members that
  buffer is ciphertext and gets replaced, never decrypted in place.
- **KDF parameters** — salt, iterations, Argon2 `t`/`m`/`p`. Public per the ODF
  encryption-data XML; they ship inside the file.
- **`encrypt`'s salt and IV** — written to the manifest in the clear.

## Residue

- The `Sha1`/`Sha256` hasher buffers the raw password until `finalize` and drops unzeroized —
  `BlockBuffer::reset` only zeroes the position, not the bytes.
- `sha1::compress` / `sha2::compress256` spill their message schedule; `W[0..16]` *is* the
  message block verbatim.

`digest`/`sha1`/`sha2` at 0.10 expose no `zeroize` feature — checked, zero references in all
three manifests. Hand-rolling the hash over the public `compress` function would remove the
first copy and leave the second, buying nothing an attacker reading the stack would notice.
**Do not reimplement SHA here.** In practice the KDF that runs next overwrites that stack
region within microseconds.

`start_key` writes the digest straight into the wrapper's heap buffer via `finalize_into`, so
no stack copy of the *digest* survives.

## Enforcement

**None automated for secure-gate usage.** CI runs `fmt`, `clippy -D warnings` and the test
matrix, none of which knows about wrapper discipline. Caught in review only.

## Verify

```bash
cargo build --locked --no-default-features                    # secure-gate compiles either way
cargo build --locked --no-default-features --features crypto-ops
cargo clippy --locked --all-targets --no-default-features -- -D warnings
cargo clippy --locked --all-targets --no-default-features --features crypto-ops -- -D warnings
cargo test  --locked --no-default-features --features crypto-ops
cargo fmt --all --check
```

After a dependency change, also the MSRV build and the crate-count check — secure-gate is
unconditional, so its graph moves the *detection-only* number, which is this crate's headline
claim.

## What did not transfer

- **The `rand` / `ct-eq` / `encoding` guidance** in the global skill. All three are off here and
  measurably unused; enabling one is a decision to argue for.
- **Newtypes.** Four interchangeable roles is below the global skill's threshold for settling
  the question, and `dynamic_newtype!` adoption stays *deferred, not rejected*. If you add a
  wrapper whose role could be confused with an existing one, that is the case for settling it
  rather than adding a fifth alias.
- **Tier 2 and Tier 3 guidance**, which has no call sites to apply to.
