# Feedback on src/parsers/lnk.ts — review iteration 3

Iteration 2 fixed the volume label. One defect remains, and my earlier feedback
pointed you at the wrong place — apologies. `readString()` is **correct**; it
already advances `charCount * 2` for Unicode. Do not change it.

## The actual defect: `pos` is never advanced past LinkInfo

At line 192 the code computes where LinkInfo ends:

```ts
linkInfoEnd = pos + linkInfoSize;
```

and then nothing ever assigns that to `pos`. `linkInfoEnd` is a dead variable —
written once, never read. So when the StringData section begins reading at
`pos`, `pos` is still pointing at the **start** of the LinkInfo block rather
than just past its end.

For the fixture that is an offset of 399 where it should be 477, a shift of 78
bytes — exactly `linkInfoSize`. Every StringData field is then read from the
wrong place, which is why:

- `description` comes back `""` — it reads LinkInfo bytes, not the name
- `workingDirectory` comes back `"est argC:\Windows\System32\notepad.exe̔"` —
  the tail of `-test arg` followed by the icon path, because by then the cursor
  has drifted into the *arguments* field
- `machineId` comes back `null` — the ExtraData scan begins mid-structure, so
  the TrackerDataBlock signature `0xA0000003` is never found

All three are one bug, not three.

## The fix

Assign `pos = linkInfoEnd` after the LinkInfo block closes and before the
StringData section begins — that is, between the closing braces at line 195 and
the `// StringData` comment at line 197.

Make sure it is reached on **every** path through the LinkInfo block, including
the ones that warn and bail out early: a truncated or malformed LinkInfo must
still leave `pos` at a sane place rather than rewinding StringData into the
middle of it. `linkInfoEnd` is initialised to `pos` at the top, so when
`hasLinkInfo` is false the assignment is harmless.

## Definition of done

1. `npx vitest run src/parsers/lnk.test.ts` passes, matching
   `fixtures/lnk/expected.json` exactly on all 14 fields. In particular:
   `description` is `"Generated fixture"`, `workingDirectory` is
   `"C:\Windows\System32"`, `arguments` is `"-test arg"`, `iconLocation` is
   `"C:\Windows\System32\notepad.exe"`, and `machineId` is `"TESTHOST"`.
2. `npm run typecheck` and `npm test` both pass, with no test weakened, skipped
   or deleted.
3. `git diff --stat -- fixtures/` stays empty.

Run `npm run typecheck` and `npm test` at the end and report the real output.
