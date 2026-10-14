"""Generate `src/ms1252.rs`'s fallback table from a LibreOffice checkout.

    python tools/gen_ms1252.py <LibreOffice core checkout>

LibreOffice's legacy SHA-1 read ladder hashes the password as MS-1252, converted by
`OUStringToOString(.., RTL_TEXTENCODING_MS_1252)` with `OUSTRING_TO_OSTRING_CVTFLAGS`
(`include/rtl/string.h`). That conversion is `convertUnicodeToChar`
(`sal/textenc/convertsimple.cxx`): a direct table lookup, then -- because the flags carry
`UNDEFINED_REPLACE` -- one retry through `aImplRepCharTab`, a "similar character" table.

The direct tables are small and written by hand in `src/ms1252.rs`. The fallback table has
~290 rows, most of which land on nothing MS-1252 can hold, so this script resolves it to
just the characters that *do* end up as a byte: (char, byte) pairs.

It simulates LibreOffice's binary search (`ImplGetReplaceChar`) over the table **as
written**, for every BMP code point, rather than reading the rows as a map. If the table
were ever out of order upstream, a map would answer characters the real search misses.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROW = re.compile(r"\{\s*(0x[0-9A-Fa-f]+),\s*(0x[0-9A-Fa-f]+)\s*\}")


def table(src: str, name: str) -> list[tuple[int, int]]:
    start = src.index(name)
    body = src[start:src.index("};", start)]
    return [(int(a, 16), int(b, 16)) for a, b in ROW.findall(body)]


def main() -> int:
    core = pathlib.Path(sys.argv[1])
    textenc = (core / "sal/textenc/textenc.cxx").read_text(encoding="utf-8")
    simple = (core / "sal/textenc/convertsimple.cxx").read_text(encoding="utf-8")

    # aImplMS1252ToCharTabEx rows are { uni, byte, byte2 }; byte2 is 0 for all of them.
    ex = {}
    start = textenc.index("aImplMS1252ToCharTabEx[")
    body = textenc[start:textenc.index("};", start)]
    for a, b, c in re.findall(r"\{\s*(0x[0-9A-Fa-f]+),\s*(0x[0-9A-Fa-f]+),\s*(\w+)\s*\}", body):
        assert c == "0", "a two-byte MS-1252 mapping appeared upstream"
        ex[int(a, 16)] = int(b, 16)
    assert len(ex) == 27, len(ex)

    def direct(c: int) -> int | None:
        if c < 0x80 or 0xA0 <= c <= 0xFF:
            return c
        return ex.get(c)

    rep = table(simple, "aImplRepCharTab[]")

    def get_replace(c: int) -> int:
        lo, hi = 0, len(rep) - 1
        while True:
            mid = (lo + hi) // 2
            u, r = rep[mid]
            if c < u:
                if mid == 0:
                    break
                hi = mid - 1
            elif c > u:
                lo = mid + 1
            else:
                return r
            if lo > hi:
                break
        return 0

    out = []
    for c in range(0x80, 0x10000):
        if 0xD800 <= c <= 0xDFFF or direct(c) is not None:
            continue
        r = get_replace(c)
        if r and direct(r) is not None:
            out.append((c, direct(r)))

    print(f"// {len(out)} rows, from {len(rep)} in aImplRepCharTab.")
    for c, b in out:
        print(f"    (0x{c:04X}, 0x{b:02X}),")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
