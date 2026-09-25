# Making 4NSEC fast and able to take 10 GB

Goal: open multi-gigabyte artifacts (a 2–10 GB Security.evtx, a whole KAPE
collection) in a browser tab without freezing or crashing it, keep the
results exactly EZ's, and make the page itself instant.

## Where it stands (measured, not guessed)

Real 20.1 MB System.evtx, 46,781 events, current code:

| Measure | Now | What it means at 10 GB |
|---|---|---|
| Parse speed | 8.6 MB/s, one thread | ~20 minutes |
| Memory per event | 1,842 B (4.1× the file) | ~41 GB: the tab dies at ~1 GB of input |
| Worker → UI copy | every row cloned once more | memory doubles, UI stalls |
| Search on an event field | 900 ms / 47k rows, on the UI thread | minutes per keystroke, page frozen |
| Row cap | 5,000,000 | a 10 GB log has ~25M events |

Why: every record's XML is rendered to text, scanned by ~10 regexes, then
parsed back into a tree for the maps (the work is done twice); every row
keeps its full XML and payload text; all rows are held twice (worker and
page); search, sort and Sigma run on the page's thread.

## Architecture after the change

```
 File (never loaded whole)
   │ reader.bytes(offset, len)
   ▼
 Worker pool  ── each parses a range (EVTX: 64 KB chunks are independent)
   │ rows
   ▼
 Column store in the worker   numbers/dates in typed arrays,
   │                           repeated strings stored once (dictionary),
   │                           heavy text (XML, payload) NOT kept:
   │                           rebuilt from the file by offset when needed
   ▼
 Query engine in the worker    search, column filters, Sigma, sort
   │                           → a list of matching row numbers
   ▼
 Page asks only for the ~60 rows on screen, the one row you click,
 or an export stream. Nothing else crosses to the page.
```

## Phases

**1. Data engine in the worker (every parser benefits)**
- Rows stay in the worker; the page gets counts and windows of rows.
- Column store with dictionary-encoded strings (event logs repeat provider,
  channel, computer, user... millions of times).
- Search, column filters, Sigma and sort run in the worker; the page never
  freezes. A new keystroke cancels the previous query.
- Results stream in while parsing: first rows in under a second, a progress
  bar with MB/s and ETA, and Cancel.
- Row details fetched on click; export streamed in pieces (no giant string).
- Row cap lifted: bounded by memory, and the app says when it is close.

**2. EVTX speed**
- Decode each record once: fields and maps from one pass, no regex rescans;
  XML text built only for the rows you look at, export, or text-search.
- Parse in parallel across CPU cores by chunk ranges, merged in order.
- Event-data fields (TargetUserName, CommandLine...) stored compactly so
  searching them never re-decodes.
- Output checked unchanged against the Windows-rendered XML oracle and the
  SigmaHQ regression set.

**3. Beyond memory** — per-artifact memory budget; heavy columns always
rebuilt from the source file; later, optional spill of the column store to
the browser's private disk (OPFS) for the largest cases.

**4. Product**
- Drop a whole KAPE folder (or pick it): every artifact found recursively,
  recognised, hives paired with their logs, parsed in a queue with progress.
- A collection inventory: what was found, which EZ tool it maps to, row
  counts, warnings.
- Works offline once opened (installable), for air-gapped machines.
- Next: one merged timeline across everything loaded.

**5. Security (evidence is hostile input)**
- A Content-Security-Policy with `connect-src 'none'`: the browser itself
  refuses any network request, so "nothing leaves the machine" is enforced,
  not just promised.
- Parsers stay in workers (no DOM), with size and depth limits; malformed
  input must never hang or blow memory: fuzz every parser.
- Regular expressions from Sigma rules or searches run in the worker, where
  a runaway one can be cancelled.
- CSV formula injection: event text can start with `=`, `+`, `-`, `@` and run
  in Excel. EZ does not guard against it. Suggest an export option (default
  off, to stay identical to EZ unless you decide otherwise).
- Chain of custody: SHA-256 of each input and the tool version in exports.

**6. Testing**
- Benchmark suite with budgets (MB/s, bytes/event, time-to-first-row) and a
  generator for multi-GB EVTX built from real chunks.
- Fuzz tests: random byte damage must yield warnings, never a throw or hang.
- Parity harness: point it at a folder of EZ CSV outputs and the same
  artifacts, it diffs every column. Running EZ's tools on your KAPE output
  once gives the strongest oracle this project can have.
- Browser end-to-end check of the big-file path.

## Targets

| Measure | Target |
|---|---|
| EVTX throughput | ≥ 60 MB/s on 8 cores (10 GB in ~3 min) |
| Resident memory | ≤ 250 B per event (10 GB ≈ 6 GB total, spread over workers) |
| First rows visible | < 1 s after drop |
| Search / filter | never blocks the page; < 1 s per million events for stored columns |
| Output | identical to today's verified output |
