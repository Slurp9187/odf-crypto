# Handoff: perf work, rc.15 (not for merge)

This branch exists only to carry the benchmark harness and this note to another
machine. Do not merge it; delete it when #113-#115 land.

## State

| PR | branch | base | status |
| --- | --- | --- | --- |
| #113 zip 9.1.3, offset-0 open (closes #112) | `ccr-f3af097f-0ct47o` | `main` | draft, green locally |
| #114 streaming perf (ghash 0.6, passthrough, adaptive deflate) | `perf-streaming` | #113's branch | draft, green locally |
| #115 parallel Argon2 lanes (argon2 0.6) | `perf-argon2` | #114's branch | draft, green locally |

Retarget each PR to `main` as the one below it merges.

## Open merge condition: the LibreOffice gates (#114, and #115 by inheritance)

#114 changed bytes LibreOffice must still open: per-entry `decrypt_to` output
(deflated members are now copied, not re-deflated) and the `encrypt_to` /
`reencrypt_to` payload (stored DEFLATE blocks for compressed chunks). The
container had no LibreOffice. On the workstation, from `perf-argon2`:

    set ODF_CRYPTO_LO_GATE_DIR=%TEMP%\lo-gate
    cargo test --features crypto-ops --lib -- --ignored write_lo_gate_outputs
    python tests\goldens\validate_decrypt_to.py %TEMP%\lo-gate
    cargo test --features crypto-ops --lib -- --ignored write_lo_gate_output
    "C:\Program Files\LibreOffice\program\python.exe" tests\goldens\validate_encrypted_outputs.py %TEMP%\lo-gate

Read each script's docstring first. They are the authority on arguments and env vars.
If both pass, tick the box in #114's body. Then update README's sentence that says
the verdict predates rc.15, and #114's CHANGELOG bullet "The LibreOffice gate has
not been re-run".

Also worth doing on Windows: re-measure the crate counts with `--target`.
README/CLAUDE.md now give crypto-ops 67/66/69 and cli 79/81/85
(Windows/Linux/macOS).

## Re-running the benchmarks

`bench112.rs` is a throwaway example over the public API; `ab.sh` runs two
builds interleaved and prints medians. Each build is a copy of the tree with
the example added:

    mkdir ../bench && cp -r . ../bench/new   # (and an older commit as ../bench/old)
    cp perf-harness/bench112.rs ../bench/new/examples/
    printf '\n[[example]]\nname = "bench112"\nrequired-features = ["crypto-ops"]\n' >> ../bench/new/Cargo.toml
    (cd ../bench/new && CARGO_TARGET_DIR=../target-new cargo build --release --locked --features crypto-ops --example bench112)
    cp perf-harness/ab.sh ../bench/   # ab.sh expects target-<name> dirs beside it

Modes: `run FILE N` (decrypt_to MiB/s; ms with MS=1), `re FILE N`
(reencrypt_to), `encp PLAIN N` (encrypt_to MiB/s and output size), and
`make OUT` (a 64 MiB wholesome package). PW overrides the password ("pw"). ab.sh
takes `MODE=`. It is bash (Git Bash on Windows).

Inputs:
- `python make_perentry.py tests/goldens/lo-legacy-aes-cbc.odt OUT 64`: a 64 MiB
  legacy AES-CBC package, password `password`. Needs `cryptography`.
- `python make_plain.py tests/goldens/lo-unencrypted.odt OUT lo|stored`: a
  LibreOffice-like (deflated XML plus JPEG-like pictures) or stored-XML plain
  package.

Both read `/usr/share/mime/packages/freedesktop.org.xml` as bulk XML. On Windows,
point them at any large XML file instead.

## Figures recorded (Linux container, 4 vCPU)

- wholesome `decrypt_to`: 421 to 773 MiB/s.
- per-entry `decrypt_to`: 1835 to 428 ms.
- per-entry `reencrypt_to`: 2432 to 400 ms.
- `encrypt_to`, LibreOffice-like package: 27 to 411 MiB/s, output +0.012%.
- `encrypt_to`, stored-XML package: unchanged.
- LibreOffice-golden decrypt with the Argon2 KDF: 203 to 90 ms.

Absolute numbers drifted between runs; ratios held.

## Follow-ups not done

- Parallel PBKDF2 across per-entry rows. About 280 ms for 7 rows on
  `lo-legacy-aes-cbc.odt`. They are derived member by member, inside each
  member's checks, so it needs a restructure.
