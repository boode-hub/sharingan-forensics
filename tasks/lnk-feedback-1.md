# Feedback on src/parsers/lnk.ts — review iteration 1

The parser currently produces **zero rows** for the fixture. One defect, and it
fails every real shortcut, not just the test.

## Defect: the LinkCLSID comparison is case sensitive

`run()` reports this warning and then no rows:

```
offset 4: invalid LinkCLSID 00021401-0000-0000-c000-000000000046
```

That value **is** the correct Shell Link CLSID. The check is rejecting a valid
shortcut purely because of letter case: `guid()` in `src/core/binary.ts` builds
its string with `toString(16)`, which produces **lowercase** hex, while the
expected constant in `lnk.ts` is written with uppercase `C000`.

Fix the comparison so case cannot matter — lowercase both sides before
comparing, or compare the 16 raw bytes rather than a formatted string. Do not
change `src/core/binary.ts`; `guid()` returning lowercase is correct and other
parsers depend on it.

Apply the same care to `sniff()`. It currently returns `false` for this fixture,
which is the same bug: the app's `detect()` would report a valid `.lnk` as
unrecognised even once `parse()` is fixed. Both code paths must accept the CLSID
regardless of case.

## Definition of done

1. `npx vitest run src/parsers/lnk.test.ts` passes, with the golden test matching
   `fixtures/lnk/expected.json` exactly.
2. `lnk.sniff(buf, 'notepad.lnk')` returns `true` for the fixture.
3. `npm run typecheck` and `npm test` both pass with no test weakened, skipped
   or deleted.
4. `fixtures/` is not modified — `git diff --stat -- fixtures/` stays empty.

Run `npm run typecheck` and `npm test` at the end and report the real output.
