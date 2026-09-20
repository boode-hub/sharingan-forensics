# Feedback on src/parsers/lnk.ts — review iteration 2

The CLSID fix worked: the parser now returns a row. Two defects remain.

## Defect 1: StringData advances by the wrong number of bytes

Actual versus expected:

```
arguments         ""                                          should be "-test arg"
description       ""                                          should be "Generated fixture"
iconLocation      ""                                          should be "C:\Windows\System32\notepad.exe"
workingDirectory  "est argC:\Windows\System32\notepad.exe̔"   should be "C:\Windows\System32"
```

`workingDirectory` containing `est arg` — the tail of `-test arg` — followed by
the icon path is the giveaway. The strings are being read at drifting offsets,
so each one swallows part of the next.

The cause is the character count being treated as a byte count. In this fixture
the LinkFlags are `0x40F7`, so **IsUnicode (`0x80`) is set** and the data is
UTF-16LE. For each StringData entry:

```
u16 count        <- COUNT OF CHARACTERS, not bytes
count * 2 bytes  <- when IsUnicode is set
```

So the cursor must advance by `2 + count * 2`, and the text is
`utf16(buf.subarray(pos + 2, pos + 2 + count * 2))`. Advancing by `2 + count`
drifts by one byte per character, which is exactly the corruption above. When
IsUnicode is clear the entries are single-byte and advance by `2 + count`.

Remember the entries appear only when their flag is set, and always in this
order: NAME, RELATIVE_PATH, WORKING_DIR, ARGUMENTS, ICON_LOCATION. For this
fixture RELATIVE_PATH is absent (`0x40F7 & 0x08` is 0), so nothing may be
consumed for it.

## Defect 2: the volume label is decoded with the wrong character width

```
volumeLabel  "䌀尺楗摮睯屳祓瑳浥㈳湜瑯灥摡攮數"   should be ""
```

Those glyphs are the ASCII bytes of `C:\Windows\System32\notepad.exe` being
decoded as UTF-16 — two single-byte characters combined into one wide character.
The VolumeID label at `VolumeLabelOffset` is a **single-byte, NUL-terminated**
string; read it with `ascii()`, not `utf16()`.

`VolumeLabelOffset` sits at offset 12 inside the VolumeID structure and is
relative to the **start of the VolumeID**, not to the LinkInfo block. In this
fixture the label is genuinely empty, so the correct result is `""`.

Note the special case: when `VolumeLabelOffset` equals `0x14`, the real label is
a **UTF-16** string whose offset is the `u32` at VolumeID offset 16 instead.
That does not apply here, but handle it rather than mis-decoding.

## Defect 3, a consequence of defect 1

```
machineId  null   should be "TESTHOST"
```

ExtraData blocks begin immediately after StringData, so the drift from defect 1
leaves the scan starting mid-structure and the TrackerDataBlock
(signature `0xA0000003`) is never found. Fixing defect 1 should fix this. If it
does not, the MachineID is 16 single-byte characters at offset 16 within that
block, NUL padded — `TESTHOST` followed by eight NUL bytes here.

## Definition of done

1. `npx vitest run src/parsers/lnk.test.ts` passes, matching
   `fixtures/lnk/expected.json` exactly, all 14 fields.
2. `npm run typecheck` and `npm test` both pass, with no test weakened, skipped
   or deleted.
3. `git diff --stat -- fixtures/` stays empty.

Run `npm run typecheck` and `npm test` at the end and report the real output.
