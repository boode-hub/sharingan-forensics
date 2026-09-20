# Task: fix `sniff()` in `src/parsers/lnk.ts` — wrong CLSID byte order

`lnk.sniff()` returns **false for every real `.lnk` file**. It was not caught
because `detect()` falls back to matching the `.lnk` extension, so the app
appears to work on files that still have their extension.

That fallback is exactly what a forensic tool cannot rely on. A shortcut carved
from unallocated space, recovered from a `$I` Recycle Bin entry, or renamed
during export has no extension, and content detection is the only thing left.
Today those files are reported "unrecognised".

## The defect

The Shell Link CLSID is `00021401-0000-0000-C000-000000000046`. A GUID is
stored on disk in **mixed-endian** form: the first 32-bit field is
little-endian, the two 16-bit fields are little-endian, and the final eight
bytes are big-endian. So the on-disk bytes at offset 4 are:

```
01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46
```

Verified against two independent files — the committed fixture
`fixtures/lnk/notepad.lnk` and a real Windows shortcut — both begin with
`01 14 02 00` at offset 4.

The parser instead compares against:

```
00 02 14 01 00 00 00 00 C0 00 00 00 00 00 00 46
```

which is the human-readable text order, not the on-disk order. The first four
bytes are reversed, so the comparison can never succeed.

## The fix

Correct the expected byte array to the on-disk order above. Better still, use
the existing `guid()` helper in `src/core/binary.ts`, which already implements
Microsoft's mixed-endian decoding, and compare the resulting string
case-insensitively against `00021401-0000-0000-c000-000000000046`. That keeps
one implementation of GUID byte order in the codebase instead of two.

Do not change `src/core/binary.ts` — `guid()` is correct and other parsers rely
on it.

## Definition of done

1. `lnk.sniff(buf, 'anything')` returns **true** for
   `fixtures/lnk/notepad.lnk`, including when the filename argument has no
   `.lnk` extension at all.
2. It returns **false** for random bytes and for a file whose first four bytes
   are `4C 00 00 00` but whose CLSID does not match.
3. Add a test asserting point 1 with a filename such as `carved-0001.bin`, so
   the extension fallback cannot mask the failure again.
4. `npm run typecheck` and `npm test` both pass, no test weakened or skipped.
5. `git diff --stat -- fixtures/` stays empty.

Run `npm run typecheck` and `npm test` at the end and report the real output.
