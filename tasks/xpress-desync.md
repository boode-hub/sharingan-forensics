# Task: fix the Xpress Huffman decoder desync in `src/core/xpress.ts`

Read `AGENTS.md` first. Do not touch anything under `fixtures/`. Every existing
test must still pass when you are done.

## The bug in one sentence

`xpressHuffmanDecompress()` decodes the first 64 KiB chunk byte-for-byte
correctly, and the compressed stream stays perfectly in sync all the way to the
end, but the decoded **content** starts diverging in a later chunk — so a match
is being copied from the wrong place while the bitstream itself stays aligned.

## Reproducing it

The sample is committed at:

```
fixtures/prefetch/DEVENV.EXE-854D7862.pf
```

51993 bytes. It is a real Windows 10 Prefetch file from Eric Zimmerman's own
test corpus (MIT licensed). Strip the 8-byte `MAM\x04` header; the declared
uncompressed size at offset 4 is **380690**, which is **6 chunks**.
`unwrapMam()` already handles the header.

## What is provably CORRECT right now — do not "fix" these

1. **Chunk 0 decodes byte-perfectly.** After decompression the body starts with
   version `30`, signature `SCCA`, and the name hash at offset 76 reads
   `854D7862` — which matches the `854D7862` in the file's own name. That is an
   independent confirmation that the first chunk is exact.
2. **Total output length is exactly 380690**, matching the declared size, so the
   stream never loses or gains bytes overall.
3. Every chunk's Huffman table is found at the right byte: the decoder walks all
   6 chunks without hitting an invalid prefix code or an over-subscribed table.

## The symptom

Filename strings live at the offset in the header at byte 100, for the length at
byte 104. They are NUL-terminated UTF-16LE paths.

The **file-metrics entry count at header offset 88 says there are 403 entries**,
and in a valid Prefetch file the number of filename strings equals that count.
The current decoder yields **592** strings — the extra ones are corruption
splitting real paths apart on stray NUL bytes.

Early paths decode perfectly, for example:

```
\VOLUME{01d1217a9c4c6779-8c9f49ec}\PROGRAM FILES (X86)\MICROSOFT VISUAL...
```

The last one decodes as the single garbage character `ʩ`.

## Already ruled out — do NOT spend time re-testing these

- **Huffman table construction.** Every chunk's table has Kraft sum exactly 1,
  so the canonical code assignment and the nibble order (low nibble = even
  symbol) are both right.
- **Extended-length encodings.** When the length nibble is 15 a byte is read,
  and if that byte is 255 a u16 follows. Variants `u16 - 15`, `u16 + 15` and
  `u16 - 18` were all tried: each fails outright with an invalid prefix code or
  an over-subscribed table. Plain `u16` is the only one that survives.
- **Refill timing.** Refilling with `if (bitcnt < 16)` one word at a time is
  required. The eager `while (bitcnt <= 16)` version breaks the chunk offsets,
  because extended-length bytes are read from the same cursor the bit reader
  uses.
- **Chunk padding.** `if (bitcnt < 16) pos += 2` after each chunk is required to
  land on the next chunk's table.
- **Match clamping.** SUPERSEDED — see "THE ANSWER" below. Clamping appeared
  necessary only because the distance bits were consumed in the wrong order;
  with that corrected, do not clamp.
- **Large distances.** The maximum distance bit-width is 15 and the largest
  distance observed is 65508, inside the 64 KiB window. Chunk 0 already uses
  distances above 40000 and is completely clean, so big distances are not by
  themselves the problem.
- **Silently clamping the distance** (`distance = min(distance, CHUNK)`) is NOT
  a fix. It was tried; it corrupts data quietly instead of failing loudly, which
  is unacceptable in forensic code.

## Where to look

Because the stream stays aligned but the bytes come out wrong, suspect the
**copy**, not the bit parsing. Worth considering:

- Whether the LZ77 window is supposed to reset at each 64 KiB chunk, making
  distances chunk-relative rather than absolute across the whole output.
- Whether a match that reaches back across a chunk-start boundary needs
  different handling in [MS-XCA].
- Whether `distance` is measured from the chunk start rather than the current
  output position.

## THE ANSWER — found in the reference implementation

Stop hypothesising; the cause is confirmed. The authoritative reference is:

  https://raw.githubusercontent.com/fox-it/dissect.util/main/dissect/util/compression/lzxpress_huffman.py

Its inner loop does this, in this exact order:

```python
offset = (1 << symbol) + bitstring.lookup(symbol)   # PEEK the distance bits
if length == 15:
    length = ord(bitstring.read(1)) + 15            # read the extended-length BYTE
    if length == 270:
        length = _read_16_bit(bitstring.source)
bitstring.skip(symbol)                              # only NOW consume the distance bits
length += 3
```

Note `lookup()` **peeks** the distance bits and `skip()` consumes them *after*
the extended-length bytes have been read. Our implementation consumes the
distance bits immediately, before reading those bytes. That ordering changes
when the bit reader refills, which changes `pos`, and `pos` is exactly the
cursor the extended-length byte is read from. The two orderings agree whenever
the length nibble is not 15 and disagree whenever it is — which is why chunks
containing many extended lengths are the corrupt ones.

Two things to change:

1. Peek the distance bits, read any extended-length bytes, and only then
   consume the distance bits.
2. Do **not** clamp a match to the chunk end. The reference tracks
   `chunk_size += length` with the full length and lets the final match of a
   chunk overshoot 65536; the loop condition is `while chunk_size < 65536`.
   Our current clamp truncates those matches.

Keep everything else as it is.

## Definition of done

1. The filename-strings region splits into exactly **403** NUL-terminated
   strings, matching the file-metrics count at header offset 88. The current
   broken output gives 592, which is how you know it is wrong.
2. Every one of those paths is clean readable text — no stray glyphs, and the
   last string is a real path rather than `ʩ`.
3. Decompressed length stays exactly 380690 and the body still reads version
   30, `SCCA`, hash `854D7862`.
4. `npm run typecheck` and `npm test` both pass, with no test weakened, skipped
   or deleted.
5. `git diff --stat -- fixtures/` stays empty.

Add a test to `src/core/xpress.test.ts` that reads the committed sample and
asserts points 1 and 3, so the fix cannot regress.

When it works, also delete the "INCOMPLETE" `ponytail:` note at the top of
`src/core/xpress.ts` and the multi-chunk warning block in
`src/parsers/prefetch.ts`, since the caveat will no longer be true.

Run `npm run typecheck` and `npm test` at the end and report the real output.
