# Sharingan Forensics — Specification

A browser-based replacement for the Eric Zimmerman toolset. Drop in an artifact,
get a parsed table.

## Non-negotiables

1. **Nothing leaves the machine.** No upload, no backend, no telemetry, no
   analytics. Every byte is parsed in the browser. This is what makes the tool
   usable on evidence at all, and it is the first thing a reviewer checks. A
   `fetch()` to any origin in parser or UI code is a failed review.
2. **Partial output beats an exception.** A corrupt chunk costs that chunk, not
   the file. Parsers emit what they recovered and name what they could not via
   `ctx.warn()`. See `src/core/registry.ts` — `run()` enforces this even for a
   parser that throws anyway.
3. **Read-only.** Nothing writes back to a user's file. Exports are new files.
4. **No new runtime dependencies** without a line in the PR explaining what
   handwritten code it replaces. `DataView`, `TextDecoder`, `SubtleCrypto`,
   `DecompressionStream`, Web Workers and OPFS already cover most of this
   problem. Exceptions expected: `sql.js` (P5), nothing else foreseen.
5. **Offsets are evidence.** Every row carries the byte offset it came from.
   An analyst who cannot point at the bytes cannot testify to the finding.

## Parser contract

Defined in [`src/core/types.ts`](src/core/types.ts). One object per artifact:

```ts
export const prefetch: Parser = {
  id: 'prefetch',
  name: 'Prefetch',
  ezTool: 'PECmd',
  extensions: ['.pf'],
  columns: [ { key: 'executable', label: 'Executable' }, /* ... */ ],
  sniff: (head, filename) => magic(head, 'SCCA', 4) || magic(head, 'MAM\0'),
  async *parse(reader, ctx) { yield row; },
};
```

Rules for every parser:

- `parse` is an async generator. Yield rows as they are found; never build the
  whole array first. A 2 GB `$MFT` must not materialise in memory.
- Never `throw` for malformed input — `ctx.warn(offset, why)` and continue to
  the next record. Throw only for a programming error.
- Read through `reader.bytes()`. Never assume the whole file is in memory.
- Check `ctx.signal?.aborted` in any loop that can run long.
- Use `Cursor` from `src/core/binary.ts` for field reads. It returns 0 past the
  end and sets `.overran` rather than throwing — check it before trusting a record.
- Timestamps are `Date | null`, never strings and never `0`. `null` means
  "not recorded", which is forensically different from the epoch.
- Every `columns[].key` must appear in the rows. Extra keys not in `columns`
  are dropped from the grid but kept in exports.

## Tool coverage

Status: **done** · **wip** · **todo** · **n/a** (needs a live OS, out of scope
for a browser).

| EZ tool | Artifact | Phase | Status |
|---|---|---|---|
| PECmd | Prefetch `.pf` (incl. MAM/Xpress-Huffman) | P1 | todo |
| LECmd | Shortcuts `.lnk` | P1 | todo |
| JLECmd | `*.automaticDestinations-ms`, `*.customDestinations-ms` | P1 | todo |
| RBCmd | Recycle Bin `$I`, `INFO2` | P1 | todo |
| RecentFileCacheParser | `RecentFileCache.bcf` | P1 | todo |
| Registry Explorer | Registry hives (`regf`) | P2 | todo |
| rla | Hive transaction logs `.LOG1`/`.LOG2` | P2 | todo |
| RECmd | Batch queries over hives | P2 | todo |
| AmcacheParser | `Amcache.hve` | P2 | todo |
| AppCompatCacheParser | ShimCache in `SYSTEM` | P2 | todo |
| SBECmd / ShellBags Explorer | Shellbags in `USRCLASS.DAT`/`NTUSER.DAT` | P2 | todo |
| EvtxECmd | `.evtx` (+ event maps) | P3 | todo |
| MFTECmd | `$MFT`, `$J`, `$Boot`, `$SDS`, `$I30`, `$LogFile` | P4 | todo |
| SQLECmd | SQLite + map files | P5 | todo |
| WxTCmd | `ActivitiesCache.db` | P5 | todo |
| SrumECmd | `SRUDB.dat` (ESE) | P5 | todo |
| SumECmd | SUM `.mdb` (ESE) | P5 | todo |
| SDB Explorer | Shim databases `.sdb` | P6 | todo |
| bstrings | Strings from any file | P6 | todo |
| Hasher | MD5/SHA-1/SHA-256 | P6 | todo |
| iisGeolocate | IIS logs (geo needs a user-supplied MaxMind db) | P6 | todo |
| Timeline Explorer | The app's own grid + CSV/JSON import | P0 | wip |
| EZViewer | Hex + detail pane | P0 | wip |
| VSCMount, XWFIM | — | — | n/a |

## Phases

Each phase ships: parsers + unit tests against committed fixtures + a row in the
coverage table flipped to **done**. A phase is not done until `npm test` and
`npm run typecheck` are green and I have diffed the output against real EZ tool
output for at least one sample per parser.

**P0 — foundation (mine).** Contract, `Reader`, binary helpers, registry +
`run()`, worker harness, grid UI, file drop, export, CI, Pages deploy.

**P1 — self-contained binary formats.** No shared state between files, best
value per line. Prefetch needs Xpress Huffman decompression for Win10+ (`MAM\0`
header); Jump Lists need an OLE compound-file reader; LNK needs shell-item
parsing that P2 reuses for ShellBags. Build shell items as a shared module in
`src/core/shellitem.ts` from the start — ShellBags is the same code.

**P2 — registry family.** One `regf` parser unlocks six tools. Must handle
dirty hives (replay `.LOG1`/`.LOG2` before parsing, as `rla` does), big-data
(`db`) records, and `li`/`ri` index lists. Deleted-key recovery from unallocated
cells is required — Registry Explorer does it and analysts rely on it.

**P3 — EVTX.** Chunk-level parsing with per-chunk recovery, BinXML with
templates and substitution arrays. Port EZ's event maps (they are open XML) so
the common event IDs get named columns instead of raw XML.

**P4 — filesystem.** `$MFT` forces the large-file path: parse in a Worker, read
through `reader.bytes()`, apply fixup arrays, resolve parent sequences to full
paths in a second pass. Budget for multi-GB input.

**P5 — databases.** `sql.js` for SQLite. ESE (`SRUDB.dat`) is a handwritten
page/table parser — the hardest single item in the suite.

**P6 — utilities and the payoff.** The combined timeline: every parser already
emits timestamped rows, so merging them into one sortable super-timeline across
all loaded artifacts is mostly UI. This is the thing the EZ suite makes you do
by hand in Timeline Explorer, and it is the reason to build this at all.

## Testing

Fixtures live in `fixtures/<parser-id>/` with a `.expected.json` beside each
sample. Samples must be synthetic or from a public corpus with its licence
noted in `fixtures/SOURCES.md` — never real evidence.

Required per parser:

- A golden test: parse the fixture, compare to `.expected.json` in full.
- A truncation test: parse `sample.slice(0, n)` for a few `n`, assert it yields
  fewer rows, records warnings, and does not throw.
- A garbage test: parse random bytes with the right magic header, assert no
  throw and no hang.

The truncation and garbage tests are not optional. They are where every
handwritten binary parser actually fails.
