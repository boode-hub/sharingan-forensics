# Task: implement the Registry hive parser — Registry Explorer / RECmd

Read `AGENTS.md` and `SPEC.md` first, then `src/core/types.ts`,
`src/core/binary.ts` and `src/core/reader.ts`. Use the existing `Cursor`,
`filetime`, `utf16`, `ascii` and `magic` helpers — do not write your own.

Create exactly two files:

- `src/parsers/registry.ts` — exports `const registry: Parser`
- `src/parsers/registry.test.ts` — vitest tests driving the fixtures

Do **not** modify `src/core/`, do **not** touch `fixtures/`, do **not** edit
`src/parsers/index.ts`.

## PORT ERIC ZIMMERMAN'S CODE — do not invent your own parser

This platform exists to reproduce what the Eric Zimmerman tools output. Do not
derive the parser from a format specification and hope it agrees with his. Port
his logic, keeping his field names and semantics wherever they map onto our
`Parser` contract.

His source is MIT licensed and public. Read these files before writing anything:

| What | File |
|---|---|
| Hive header / base block | `Registry/RegistryBase.cs` |
| Key cells (`nk`) | `Registry/Cells/NKCellRecord.cs` |
| Value cells (`vk`), including every value type and the big-data case | `Registry/Cells/VkCellRecord.cs` |
| Subkey lists (`lf`, `lh`, `ri`) | `Registry/Lists/LxListRecord.cs` |
| Subkey lists (`li`) | `Registry/Lists/LIListRecord.cs` |
| The walker that ties it together | `Registry/RegistryHive.cs` |
| The key abstraction and its path building | `Registry/Abstractions/RegistryKey.cs` |

Raw URLs follow this shape:

```
https://raw.githubusercontent.com/EricZimmerman/Registry/master/Registry/Cells/NKCellRecord.cs
```

Pay particular attention to `VkCellRecord.cs`: value-type decoding and the
resident/big-data distinction are where a hand-rolled parser goes wrong, and
he has already handled the awkward cases.

## Scope for this task

Hive parsing and full key/value enumeration only.

**Out of scope, do not attempt:** transaction-log replay for dirty hives
(`rla`), deleted-key recovery from unallocated cells, and the RECmd batch
plugins. Each is its own later task. A dirty hive (where the two sequence
numbers in the header disagree) should still parse as far as it can, with a
warning saying the hive is dirty and may be stale.

## Fixtures

Both are committed, and both are real files from Eric Zimmerman's own MIT
licensed test corpus:

- `fixtures/registry/SAM` — 262144 bytes, a genuine clean SAM hive
- `fixtures/registry/NotAHive` — 17920 bytes, **a Windows PE executable**,
  starting with `MZ`. It must be rejected, not parsed.

## The oracle — verified by reading the raw bytes, independent of any parser

For `fixtures/registry/SAM`:

- Signature `regf` at offset 0; both sequence numbers are **61**, so the hive is
  clean
- Major version 1, minor version 3
- Root key offset 32, hive-bins size 32768
- Embedded hive name: `\SystemRoot\System32\Config\SAM`
- The root key cell is an `nk` at file offset 4132
- Root key name is `CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}`
- Root key last-written time is `2014-07-03T18:05:37.590Z`
- Root key has **1** stable subkey and **0** values; its subkey list is an `lf`
- Walking first children gives this chain, each list an `lf`:

```
CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\SAM\Domains\Account
```

with `SAM` having 3 subkeys and 2 values, `Domains` having 2 subkeys and 1
value, and `Account` having 3 subkeys and 2 values.

## Required output columns — exact keys, one row per VALUE

A key with no values still emits one row, with the value columns null, so the
key itself is visible.

```
keyPath      str   full path from the root, backslash separated, root name excluded
valueName    str   the value name, or null for a key-only row.
                   The default (unnamed) value is "(default)", as Registry Explorer shows it
valueType    str   the REG_* name, e.g. REG_SZ, REG_DWORD, REG_BINARY, REG_MULTI_SZ
valueData    str   rendered as Registry Explorer renders it: strings as text,
                   numbers as decimal, binary as uppercase hex bytes
lastWritten  date  the owning key's last-written time
offset       num   byte offset of the cell this row came from
```

## sniff()

True only when the first 4 bytes are exactly `regf`. That alone rejects
`NotAHive`. `extensions: []` — registry hives have no consistent extension
(`SAM`, `SYSTEM`, `NTUSER.DAT`, `UsrClass.dat`).

## Behaviour on bad data

Never throw. `ctx.warn(offset, message)` and continue.

- A cell whose signature is not the expected one: warn, skip that cell, keep
  walking the rest of the tree.
- A subkey or value offset pointing outside the hive: warn and skip it.
- A cycle in the key tree, which corrupt hives do contain: keep a set of visited
  cell offsets and stop descending when one repeats. **This matters** — without
  it a malformed hive hangs the browser tab.
- Cap the walk at 500000 rows and warn if the cap is hit.

## Tests

- **Golden**: parse `SAM` and assert every oracle fact listed above — the root
  key name, its last-written time, the `SAM\Domains\Account` chain, and the
  subkey and value counts at each level.
- **Rejection**: `registry.sniff()` returns false for `NotAHive`, and parsing it
  yields zero rows plus a warning rather than throwing.
- **Truncation**: parse `SAM.subarray(0, n)` for n = 100, 4096, 40000. Assert no
  throw and no hang.
- **Garbage**: 200000 random bytes with `regf` written at offset 0. Assert no
  throw and no hang.

Finally run `npm run typecheck` and `npm test` and report the real output.
