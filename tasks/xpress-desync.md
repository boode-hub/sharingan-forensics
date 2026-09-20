# Task: fix the Xpress Huffman decoder desync in `src/core/xpress.ts`

Read `AGENTS.md` first. Do not touch anything under `fixtures/`. All 50 existing
tests must still pass when you are done.

## The bug in one sentence

`xpressHuffmanDecompress()` decodes the first 64 KiB chunk byte-for-byte
correctly, and the compressed stream stays perfectly in sync all the way to the
end, but the decoded **content** starts diverging partway through chunk 3 — so a
match is being copied from the wrong place while the bitstream itself stays
aligned.

## Reproducing it

The test file is a real Windows 11 Prefetch file on this machine:

```
C:/Windows/Prefetch/ANTIGRAVITY.EXE-6247EA31.pf
```

It is 52255 bytes. Strip the 8-byte `MAM\x04` header; the declared uncompressed
size at offset 4 is **317370**. `unwrapMam()` already does this.

## What is provably CORRECT right now — do not "fix" these

1. **Chunk 0 decodes byte-perfectly.** Version `31`, signature `SCCA`, the size
   field at offset 12 equals `317370` exactly, executable name
   `ANTIGRAVITY.EXE`, run count `29`, and eight sane descending run times. The
   strongest proof: the name hash at offset 76 is `0x6247EA31`, which matches
   the `6247EA31` in the file's own name.
2. **The bitstream stays in sync to the very end.** The five chunk tables begin
   at byte offsets `0, 16921, 33569, 44051, 48337` (relative to the post-MAM
   data). The current code lands on all five exactly. These offsets were found
   independently by scanning for 256-byte windows whose 4-bit code lengths have
   a Kraft sum of exactly 1, so they are ground truth, not a guess.
3. **Total output length is exactly 317370**, matching the declared size.

## The symptom

Filename strings live at offset `177160` for `132118` bytes (read from the
header at offsets 100 and 104). They are NUL-terminated UTF-16LE paths.

The first ~138 paths decode perfectly, for example:

```
\VOLUME{01dc8b3c7f7eaf1e-107f8885}\USERS\ABDELRAHMAN.KHALID\APPDATA\LOCAL\PROGRAMS\ANTIGRAVITY\RESOURCES\APP\NODE_MODULES\NODE-PTY\BUILD\RELEASE\CONPTY_CONSOLE_LIST.NODE
```

Then corruption begins around byte **210006**, which is **13398 bytes into
chunk 3**. Characters are substituted while the text stays path-shaped:

```
ANTIGRAVITY  ->  ONTIGRA_MO-
RESOURCES    ->  RESOURCBS
NODE_MODULES ->  NODE_MODP\UGGABb3-AVIT-HANf1E_MODULES
```

The volume block (offset from header 108) is also garbage: its first 16 bytes
read as zeros and the device path length comes out 0.

## Already ruled out — do NOT spend time re-testing these

- **Huffman table construction.** Every chunk's table has Kraft sum exactly 1,
  so the canonical code assignment is being read correctly, and the nibble order
  (low nibble = even symbol) is right.
- **Extended-length encodings.** When the length nibble is 15 a byte is read,
  and if that byte is 255 a u16 follows. Variants `u16 - 15`, `u16 + 15` and
  `u16 - 18` were all tried: every one fails outright with an invalid prefix
  code or an over-subscribed table. Plain `u16` is the only one that survives.
- **Refill timing.** Refilling with `if (bitcnt < 16)` one word at a time is
  required. The eager `while (bitcnt <= 16)` version breaks the chunk offsets,
  because extended-length bytes are read from the same cursor the bit reader
  uses.
- **Chunk padding.** `if (bitcnt < 16) pos += 2` after each chunk is required to
  hit the known table offsets.
- **Match clamping.** Clamping a match to the chunk end is required; without it
  chunk 4's table offset is wrong by 18 bytes.
- **Large distances.** Max distance bit-width is 15 in every chunk and the
  largest distance seen is 65508, inside the 64 KiB window. Chunk 0 already uses
  distances up to 41392 and is completely clean, so big distances are not the
  problem by themselves.

Per-chunk statistics, if useful: match counts `7853, 8576, 5625, 1296, 1133`
and max distances `41392, 48120, 59904, 64666, 65508`.

## Where to look

Because the stream stays aligned but the bytes come out wrong, suspect the
**copy**, not the parsing. Things worth considering:

- Whether the LZ77 window is supposed to reset at each 64 KiB chunk, making
  distances chunk-relative rather than absolute over the whole output.
- Whether `distance` is off by one, or is measured from the chunk start rather
  than the current output position.
- Whether a match that would read *across* the chunk-start boundary has special
  handling in [MS-XCA].

## Definition of done

1. The filename-strings region splits into exactly **538** NUL-terminated
   strings. That number is the file-metrics entry count at header offset 88, and
   in a valid Prefetch file it equals the number of filename strings. The
   current broken output produces 782, which is how you know it is wrong.
2. Every one of those paths is clean readable text — no `ONTIGRA_MO-`.
3. The volume block yields a real device path such as
   `\DEVICE\HARDDISKVOLUME3` with a non-zero creation time and serial.
4. `npm run typecheck` and `npm test` both pass, all 50 tests.
5. The existing real-file assertions in `src/parsers/prefetch.test.ts` still
   hold: 8 rows, hash `6247EA31`, version 31, run count 29.

When it works, also delete the "INCOMPLETE" `ponytail:` note at the top of
`src/core/xpress.ts` and the multi-chunk warning block in
`src/parsers/prefetch.ts`, since the caveat will no longer be true.
