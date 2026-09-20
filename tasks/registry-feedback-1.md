# Feedback on src/parsers/registry.ts — review iteration 1

The port is close: 68 of 69 tests pass, the hive header, the key tree and the
`SAM\Domains\Account` chain are all correct. One defect, and it is a
data-losing one.

## Defect: resident values are dropped

`registry.test.ts` fails on the value count for the `SAM` key — it reports 1
value where the hive has 2.

Read from the raw hive, the `SAM` key's value list holds exactly two `vk`
cells:

| Name | Type | Data length field |
|---|---|---|
| `C` | 3 | `0x000000a8` |
| `ServerDomainUpdates` | 3 | **`0x80000002`** |

The second one is being lost. Its data-length field has **bit 31 set**
(`0x80000000`), which is the *resident data* flag:

- The real data length is `dataLength & 0x7FFFFFFF` — here **2 bytes**.
- When that flag is set the data is **stored inline in the data-offset field
  itself**, in those same 4 bytes. There is no separate data cell to follow.

A parser that treats `0x80000002` as a length will read an absurd value, decide
the cell is corrupt, and skip it. That is almost certainly what is happening.

This matters well beyond one test. Small values — DWORDs, short strings, flags —
are resident in every real hive, so this defect silently discards a large share
of the evidence in `SYSTEM`, `SOFTWARE` and `NTUSER.DAT`. A key would appear to
have fewer values than it really has, with nothing to tell the analyst.

## The fix

Port this from `VkCellRecord.cs` rather than inferring it — his implementation
is in `.refs/VkCellRecord.cs`, which you already downloaded. Look for where he
masks the length and branches on the resident flag, and mirror that branch
exactly, including how he reads the inline bytes and how he decodes them for
each value type.

While you are in that file, confirm you also handle the **big-data (`db`)**
case, where a value's data is split across several cells listed by a `db`
record. That is the mirror image of this bug: it loses large values rather than
small ones. `.refs/DBListRecord.cs` covers it.

## Definition of done

1. `npx vitest run src/parsers/registry.test.ts` passes, including the value
   count of 2 for `SAM`.
2. `ServerDomainUpdates` appears in the output with its 2 bytes of resident
   data decoded, not skipped.
3. Add a test asserting that a value whose data-length field has bit 31 set is
   emitted with the correct data, so this cannot regress silently.
4. `npm run typecheck` and `npm test` both pass, no test weakened or skipped.
5. `git diff --stat -- fixtures/` stays empty.

Run `npm run typecheck` and `npm test` at the end and report the real output.
