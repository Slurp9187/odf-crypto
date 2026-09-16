---
name: odf-crypto-secure-gate
description: Handling password-derived key material and decrypted intermediates in odf-crypto with secure-gate wrappers. Use when touching derive_key/start_key in kdf.rs or the cipher functions in decrypt.rs/encrypt.rs, or adding a new KDF or cipher path under the 'crypto-ops' feature. Not for the password argument or the returned plaintext Vec<u8> on the public decrypt() API — those stay plain by design — and not for classify/manifest/uris/zip_tree code, which never sees key material.
---

# secure-gate in odf-crypto

**Sole authority for this topic.** [`CLAUDE.md`](../../../CLAUDE.md) carries the
project rules and points here for secret handling rather than restating any of
it; if the two ever disagree about `secure-gate`, this file is right.

## The rule: secure-gate is this crate's zeroizing primitive, full stop

odf-crypto used to reach for bare `zeroize::Zeroizing` for anything that
needed zeroizing on drop. It doesn't anymore — **wherever the code used to
zeroize, it now wraps in a secure-gate alias instead**, and every decrypted
intermediate between a cipher and the output zip is wrapped too. There is no
bare `Zeroizing` left anywhere in `src/`, and no "this one's local so plain
`Zeroizing` is enough" exception. Direct `zeroize` is gone from `Cargo.toml` —
secure-gate depends on it internally, so wrapping subsumes it.

**Dependency:** `secure-gate = "=0.9.0-rc.12"` (`Cargo.toml`),
`default-features = false, features = ["alloc"]` only — no `rand`, `ct-eq`, or
`encoding`. (All three still exist under those names in rc.12; the list is a
statement about what is off, not about what was renamed.) This crate never
generates a random *secret* (keys come from a user-supplied password;
`encrypt`'s salt and IV are public and use `aes-gcm`'s `OsRng`) and never
displays or copies key material anywhere. Unlike `sha1`/`aes`/`argon2`/etc.,
**secure-gate is not optional and not gated on the `crypto-ops` feature** —
it's an unconditional dependency, even though today only the
`crypto-ops`-gated `sensitive.rs` / `decrypt.rs` / `encrypt.rs` / `kdf.rs` use
it. The other deps in the `crypto-ops` feature list are swappable algorithm
implementations a `classify`-only consumer has no reason to pull in;
secure-gate is infrastructure, not an algorithm choice.

**Why the `=` pin, when every other dependency here is a caret range.** A caret
requirement over a *pre-release* matches later pre-releases of the same version,
and a release candidate makes no compatibility promise. The old
`"0.9.0-rc.7"` already resolved to rc.11 — measured with
`cargo update --dry-run`, not inferred — so `Cargo.lock` was the only thing
holding the old version in place, and a bare `cargo update` would have deleted
four macros out from under `sensitive.rs` with no warning. The pin then earned
itself within hours: rc.12 published the same day and changed
`Dynamic::new_with`'s signature.

**Compatibility is the lesser half of that argument.** The stronger half is
yanks: **20 of secure-gate's 54 published versions are yanked**, and a yank is
how an author says *stop using this* — sometimes for a security reason that had
to be acted on. A caret answers a yank by silently resolving to a neighbouring
pre-release, possibly the one the yank existed to move people off. `=` answers
it by failing to resolve, so a human decides. For a crate whose reason to exist
is cryptographic, a hard stop beats a silent substitution.

**Do not assume the `=` can be relaxed at a stable `0.9.0`.** The pre-release
half of the argument expires then; the yank half does not. That is a decision to
revisit with whoever maintains secure-gate, not something a stable version
number grants.

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
| `PasswordDigest` | `Dynamic<Vec<u8>>` | `src/sensitive.rs`, `pub(crate)` | **Live** — `start_key`'s return type (`kdf.rs:42`), written in place by `finalize_into` (`kdf.rs:47`), consumed by `derive_key` (`decrypt.rs:296`). |
| `DerivedKey` | `Dynamic<Vec<u8>>` | `src/sensitive.rs`, `pub(crate)` | **Live** — `derive_key`'s return type (`decrypt.rs:296`), allocated at `:305`, consumed in `decrypt_member` (`:342`). Also `encrypt`'s wholesome key (`encrypt.rs:216`). |
| `DeflatedPlaintext` | `Dynamic<Vec<u8>>` | `src/sensitive.rs`, `pub(crate)` | **Live** — returned by `decrypt_aes_gcm` (`:355`, moved in at `:389`), `decrypt_aes_cbc` (`:393`, wrapped at `:407`), `decrypt_blowfish_cfb64` (`:438`, wrapped at `:449`) and `decrypt_member` (`:342`); read inside `with_secret` to fill the next wrapper (`:220`). Also `encrypt`'s deflated-then-sealed payload (`encrypt.rs:204`). |
| `MemberPlaintext` | `Dynamic<Vec<u8>>` | `src/sensitive.rs`, `pub(crate)` | **Live** — the values of the `plain` map in `decrypt` (`:205`), built by `try_new_with` so the inflate writes into the wrapper's own slot (`:220`); `rebuild_zip` (`:618`) writes each straight from the wrapper into the zip writer (`:656`). |

> These `file:line` citations have now drifted three times and been repaired
> three times (`CHANGELOG.md` records two of them). If they drift a fourth,
> replace the line numbers with function names and let `grep` do the work — the
> function names above have been stable since the decrypt arc, while every line
> number in this table has moved at least once.

All four are `Dynamic<Vec<u8>>`, not `Fixed<[u8; N]>`. **Why `Dynamic`.**
`PasswordDigest` is 20 bytes for SHA-1 or 32 for SHA-256, decided by
`StartKeyAlg`; `DerivedKey`'s length (16/24/32) follows
`EntryEncryption::derived_key_len`; the two plaintext aliases are whatever
size the member is. None is a compile-time constant. Contrast with
encrypted-file-vault's `FileKey32` or debitleft's `DbKey32` — both `Fixed`,
because those key sizes are architectural constants the app itself picked.
Reach for `Fixed` when the byte count is fixed by your own design; reach for
`Dynamic` when it's fixed by input you don't control.

### These four are names, not types

All four are the *same* nominal type. `PasswordDigest`, `DerivedKey`,
`DeflatedPlaintext` and `MemberPlaintext` are every one of them
`Dynamic<Vec<u8>>`, so they are freely substitutable: passing a digest where a
derived key is expected compiles. What the aliases buy is a greppable name and
zeroize-on-drop, **not type safety**.

That limitation is stated here and in `sensitive.rs` rather than left to be
rediscovered, because it is exactly what upstream deleted the alias macros
over. See "Adding a new wrapper" below for the choice it opens.

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

### Reallocation residue — the one this crate *can* get wrong

`Dynamic<Vec<u8>>` zeroizes what it holds, including spare capacity, **but a
`Vec` that reallocates frees its old block unwiped**, and that block is outside
the wrapper's reach. secure-gate's own module doc says so in a table: for a
growable `Dynamic<Vec<u8>>`, "each realloc leaves the old buffer unzeroed".

Since rc.12, `Dynamic::new_with(len, f)` hands the closure a pre-zeroed
`&mut [u8]` of exactly `len` bytes, so growth is not expressible and the hazard
is gone *for values built through it*. **That is not the same as gone.** A value
grown somewhere else and then moved in with `new(owned)` has already
reallocated; `new` moves rather than copies, exactly as documented, but the
damage predates the wrapper. Both shapes exist here:

- `PasswordDigest::new_with(output_size(), |slot| ..)` (`kdf.rs:46`) — the slot
  is the wrapper's own storage and `finalize_into` fills it once.
- `MemberPlaintext::try_new_with(n, |slot| inflate_into(c, slot))`
  (`decrypt.rs:220`) — the inflate writes *into* the wrapper. This is the fix
  for a real leak: `decompress_to_vec_with_limit` grew its output as it decoded,
  so every decrypt abandoned partial copies of the user's document on the heap.
- `DerivedKey::new(vec![0u8; n])` (`decrypt.rs:305`) allocates the final length
  up front and `with_secret_mut` writes into it — no growth, so `new` is right.
- `DeflatedPlaintext::new(blob.to_vec())` allocates once at the ciphertext's
  length and decrypts in place; the CBC padding strip is a `truncate`, which
  never reallocates.
- **Still unfixed, and known:** `DeflatedPlaintext::new(raw_deflate(bytes)?)`
  (`encrypt.rs:204`) wraps a buffer `miniz_oxide::deflate::compress_to_vec`
  grew. Deflate has no declared output length to size a slot from — that is
  what `manifest:size` gives the decrypt direction and nothing gives this one —
  so closing it needs an upper bound and a truncate, not a slot. Left as is
  rather than papered over.

**The rule for a new wrapper.** If the producer writes into a buffer you supply,
use `new_with`/`try_new_with` and give it the wrapper's slot. If it returns an
owned value, `new` is a move and is correct. A closure that builds up its value
with `extend_from_slice` or repeated `push` is a leak with no symptom and no
test that can catch it — the defect msoffice-crypto found in its own RC4 key
construction, where the wrapper was doing its job and a copy of the key was
sitting outside it.

## Guards that sit next to the wrapping

`DERIVED_KEY_MIN_LEN = 1` / `DERIVED_KEY_MAX_LEN = 64` (`limits.rs:50-51`,
inside the `crypto-ops`-gated `crypto` submodule) bound `manifest:key-size`
*before* `derive_key` allocates the key buffer (`decrypt.rs:305`).
`derived_key_len` is an `i32` the manifest controls; without the bound a value
near `i32::MAX` allocates ~2 GiB and then runs PBKDF2 over all of it — a hang no
`Result` can report — before any cipher gets to reject the length. AES-256 needs
32 and Blowfish accepts at most 56, so 64 rejects nothing LibreOffice would open.
`hostile_derived_key_len_is_refused_before_allocating` (`decrypt_tests.rs`)
checks that `classify` passes the hostile value through unchanged, so the
guard — not the parser — is what the test exercises.

`inflated_len` (`decrypt.rs:534`) is the same shape for `manifest:size`, and it
exists *because* the inflate moved into a sized slot. Under the old grown-`Vec`
inflate, `INFLATE_CEILING` was the decompressor's ceiling and a hostile `size`
merely failed a comparison afterwards; now `size` **is** the allocation length,
and `vec![0u8; 9_000_000_000]` does not fail a comparison. Checked before
`decrypt_member`, so a hostile row costs a comparison rather than a 64 MiB
Argon2id — which puts it with the other pre-derivation screens `decrypt`'s
rustdoc lists. Two tests pin it, both verified by breaking what they guard:
`hostile_manifest_size_is_refused_before_allocating`, and
`overstated_manifest_size_is_rejected_rather_than_zero_padded` for the subtler
half — a slot is zero-filled, so an overstated `size` inflates short and the
decoder still reports success, leaving a tail of zeros that only the
written-vs-slot-length comparison catches.

## The pattern

> Not a doctest — nothing compiles this block, so it is verified by reading it
> against the source. Last checked against the rc.12 upgrade and the
> inflate-into-slot change.

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
    let sk = crate::kdf::start_key(password, row.start_key);
    let n = row.derived_key_len;
    if !(DERIVED_KEY_MIN_LEN..=DERIVED_KEY_MAX_LEN).contains(&n) { /* BadParameters, no allocation */ }
    let n = n as usize;
    let mut derived = DerivedKey::new(vec![0u8; n]);
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

// decrypt: the inflate writes INTO the next wrapper's slot, so the plaintext
// never exists in an unwrapped buffer. `manifest:size` is bounded first --
// it is now an allocation length, not a value checked after the fact.
let n = inflated_len(row.size)?;
let inflated = compressed
    .with_secret(|c| MemberPlaintext::try_new_with(n, |slot| inflate_into(c, slot)))?;
plain.insert(member, inflated);
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

`pbkdf2_hmac`, `hash_password_into`, the cipher constructors and `inflate_into`
all take plain `&[u8]`/`&mut [u8]`, which is what lets a third-party decoder
write straight into a wrapper's slot: `inflate_into` hands miniz_oxide's
`decompress_slice_iter_to_slice` the `&mut [u8]` `try_new_with` gave it, and
nothing in between sees a `Vec`.

## Construction

```rust
PasswordDigest::new_with(N, |slot| h.finalize_into(Output::<D>::from_mut_slice(slot)))
MemberPlaintext::try_new_with(n, |slot| inflate_into(c, slot))   // fallible fill
DerivedKey::new(vec![0u8; n])              // sized up front, filled via with_secret_mut
DeflatedPlaintext::new(blob.to_vec())      // in-place ciphers, before decrypting
out.map(DeflatedPlaintext::new)            // producing ciphers, a move
```

Per secure-gate's own docs (`src/dynamic.rs:47`), `Dynamic::new_with` exists
"for consistent API idiom, not for stack-residue avoidance" — the wrapper's
allocation is heap either way. It earns its keep in `start_key` for a different
reason: it gives `finalize_into` a buffer to write
*into*, so the digest never exists as a returned `GenericArray` on the stack
(which `finalize().to_vec()` would produce).

**Do not convert the remaining `new(...)` sites to `new_with(...)`.** The
discriminator is whether the producer *writes into a caller-provided buffer* or
*returns an owned value*. An owned return means `new` is already a move, and
`new_with` would wrap a closure around a copy from a source that stays
unprotected — strictly worse. `out.map(DeflatedPlaintext::new)` takes an owned
`Vec` from `aead`'s decrypt and is correct as it stands. (The msoffice-crypto
crate had broader `new_with` adoption as an approved plan item, checked every
candidate against this rule, and cancelled the item without converting
anything.)

The inflate went the other way for exactly this reason, and it is worth seeing
why it is not a counter-example: `MemberPlaintext` stopped using `new` not
because `new` was wrong for an owned `Vec`, but because the *producer* was
changed. miniz_oxide can write into a caller slice, so there is no longer an
owned `Vec` to move — the question is always what the producer does, never
which constructor reads better.

The rule for a new wrapper: **the function that creates sensitive material hands
back the wrapper** — `start_key`, `derive_key` and every cipher fn do — rather
than a bare value the caller has to remember to wrap.

## Adding a new wrapper

`docs/plans/odf-encryption-encrypt-2026-09-03.md`'s writer-side `encrypt()`
landed in #24 and needed **no new alias**: key derivation is shared through
`kdf.rs`, so it reuses `PasswordDigest` and `DerivedKey` verbatim, and its
deflated-then-sealed buffer is `DeflatedPlaintext` travelling the other way
(wrapped before the cipher runs, written to the zip straight from the wrapper).
Its salt and IV are deliberately *not* wrapped: both are written to the
manifest in the clear, so they are public by construction, like the KDF
parameters beside them. For the next arc that does introduce new material,
apply the same rule: if it is key material or plaintext living inside this
crate, it gets a wrapper, regardless of whether it crosses a function boundary.

1. **Alias or newtype?** secure-gate deleted `fixed_alias!` and
   `dynamic_alias!` in 0.9.0-rc.9 — **do not reach for them, they do not
   exist.** Two spellings remain:

   | Want | Write |
   |---|---|
   | A name over the wrapper (what the four here are) | `pub(crate) type X = Dynamic<Vec<u8>>;` |
   | A *distinct type*, so a swapped argument is a compile error | `dynamic_newtype!(pub(crate) X, Vec<u8>, "doc");` |

   The four existing wrappers are `type` aliases and therefore mutually
   substitutable. **Adopting `dynamic_newtype!` for them is deferred, not
   rejected** — it would make `DerivedKey` and `PasswordDigest`
   non-interchangeable, which is a real improvement, but it is a separate design
   change and rc.11 is still actively moving that macro's `derive:` surface. If
   you are adding a wrapper whose role could be confused with an existing one,
   that is the case for settling the question rather than adding a fifth alias.

2. **Is its length fixed by your own design, or by input you don't control?**
   Fixed by design (always exactly N bytes) → `Fixed<[u8; N]>`. Fixed by input
   (a manifest field, a member's size) → `Dynamic<T>`, matching the four here.
3. Declare it `pub(crate)` in `sensitive.rs` beside its peers, with a doc
   comment explaining what it is and — for a `Dynamic` — why not `Fixed`.
4. Wrap at the point of creation, in the function that produces the value
   (`start_key`, the cipher fns). If a library can write into a buffer you
   supply, hand it the wrapper's buffer via `new_with`, as `finalize_into`
   does — and size it before writing, per the residue section.
5. Check whether the new value needs to leave the crate on a public
   signature. Unlikely per "Scope" above, but a plausible `encrypt()` could
   need to hand back key material for a recovery flow — that's the one case
   that reopens the public-API question. Don't decide it silently; it's the
   same kind of call this skill's "Scope" section made once already for
   `decrypt()`, and it deserves the same explicit treatment, not a default.

## Upgrading secure-gate

It tracks release candidates and they carry breaking changes. Before bumping:

1. **`grep -rn "into_inner" src/`** — first, before any edit. rc.9 changed
   `into_inner()` to return the plain value instead of `InnerSecret<T>`, so
   protection now ends at the call. It is the only break of its kind that
   **compiles silently**. Every hit in this crate is `ZipWriter`/`Cursor`, not a
   secure-gate wrapper; confirm that is still true.
2. `grep -rn "\.len()\|\.is_empty()" src/` on anything *wrapper*-typed —
   `SecretLen` split out of `RevealSecret` in rc.8, so those need
   `use secure_gate::SecretLen;`. This crate calls them only on revealed
   `&[u8]` slices, which are unaffected.
3. `grep -rn "new_with" src/` — rc.12 changed `Dynamic::new_with` from `(f)` to
   `(len, f)`, handing the closure a pre-zeroed `&mut [u8]` instead of a
   zero-capacity `Vec`. That one is loud (`E0061`), so it needs no vigilance —
   but read it as a prompt to check whether anything *else* should now be built
   through a slot, which is how the inflate moved inside its wrapper.
4. Re-measure the crate counts (see "Verify") — secure-gate is unconditional, so
   its graph moves the *detection-only* number, which is the crate's headline
   claim. rc.11 → rc.12 moved nothing; rc.7 → rc.11 moved both figures by two.
5. Read the upstream `CHANGELOG.md` inside the new tarball
   (`~/.cargo/registry/src/*/secure-gate-<version>/CHANGELOG.md`) rather than
   docs.rs: the migration tables and `sed` scripts live there.

## Verify

Detection is the default build now, so the cryptographic paths need naming
explicitly:

```bash
cargo build --no-default-features                     # secure-gate compiles either way
cargo build --no-default-features --features crypto-ops
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --no-default-features --features crypto-ops -- -D warnings
cargo test  --no-default-features --features crypto-ops   # 112 tests, every golden KDF/cipher path
cargo fmt --all --check
```

After a dependency change, also:

```bash
cargo +1.85.0 build --locked --no-default-features --features crypto-ops   # MSRV; rc.11 is edition 2024, which needs exactly 1.85
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --locked --all-features --no-deps
cargo tree --locked -e no-dev --prefix none | grep -v '(\*)' | sort -u | wc -l   # 25 default, 59 crypto-ops (unchanged by rc.12)
```

`cargo fmt --all --check` used to fail on `main` independently of secure-gate.
It no longer does — the drift was cleared, so a failure now is yours.
