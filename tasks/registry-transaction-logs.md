# Task: registry transaction-log replay — Eric Zimmerman's `rla`

`src/parsers/registry.ts` parses hives but ignores their transaction logs. On
real collected evidence that is not a cosmetic gap: **every large hive in a
live KAPE collection is dirty**, so the values read straight from the primary
file may be stale relative to what the machine actually had.

Read `AGENTS.md` and `SPEC.md` first. This is a forensics tool: parity with his
`rla` is the definition of done.

## PORT ERIC ZIMMERMAN'S CODE

Download into `.refs/` inside this repository with `curl`, then port. Never
write outside the repository.

| What | File |
|---|---|
| Log file parsing and replay | `Registry/TransactionLog.cs` |
| Individual log entries and their dirty pages | `Registry/TransactionLogEntry.cs` |
| How the hive consumes a replay | `Registry/RegistryBase.cs`, `Registry/RegistryHive.cs` |

```bash
curl -sL -o .refs/TransactionLog.cs https://raw.githubusercontent.com/EricZimmerman/Registry/master/Registry/TransactionLog.cs
```

## Measured facts from real evidence

Taken from a real Windows 11 collection, read directly from the bytes:

| File | fileType @28 | seq1 @4 | seq2 @8 | minor @24 |
|---|---|---|---|---|
| `SYSTEM` | 0 (primary) | 113025 | 113024 | 5 |
| `SYSTEM.LOG1` | 6 (log) | 113271 | 113271 | 5 |
| `SYSTEM.LOG2` | 6 (log) | 113272 | 113272 | 5 |
| `SAM` | 0 (primary) | 120 | 120 | 5 |
| `SAM.LOG1` | 6 (log) | 118 | 118 | 5 |

What this establishes:

- A hive is **dirty when its two sequence numbers differ**. `SYSTEM` is dirty
  (113025 vs 113024); `SAM` is clean (120 = 120).
- A transaction log is identified by **fileType 6** at offset 28, against 0 for
  a primary hive. Both start with `regf`, so the signature alone is not enough.
- The logs can be far **ahead** of the hive — here by 246 sequences — which is
  exactly the data replay recovers.
- `SAM.LOG1` is *behind* its clean hive (118 < 120), so it has nothing to
  contribute. Replay must be a no-op in that case, not a corruption.
- **Minor version 5** means these are the newer log format used by Windows 8.1
  and later, not the legacy format. Port whichever branch of his code handles
  minor version 5; handle the legacy branch too if his code does.

## Required behaviour

Add log replay to the registry parser, applied **before** the hive is walked.

1. The `Parser` contract takes a single `Reader`, so the parser cannot open
   sibling files by itself. Extend the flow so the app can supply the two logs
   alongside the hive, and make replay happen when they are present. Keep the
   single-file path working unchanged when they are not.
2. Pick the logs in the right order. Both may contain entries; his code decides
   which to apply and in what sequence based on their sequence numbers. Follow
   his logic rather than assuming LOG1 then LOG2.
3. Apply only entries **newer than the hive's sequence number**, and stop at
   the first entry whose checksum or size is invalid — a truncated log tail is
   normal and must not abort the replay of the valid entries before it.
4. After replay, emit a warning stating how many entries were applied and what
   the sequence number advanced from and to. **An analyst must be told the data
   was reconstructed**, never silently handed a repaired hive as if it were the
   original.
5. When the hive is dirty and no logs were supplied, keep the existing warning
   that the data may be stale.

## Definition of done

1. Replaying `SYSTEM` with its two logs produces a hive whose sequence numbers
   agree, advanced from 113025 toward 113272, with a warning naming the count
   of entries applied.
2. Replaying `SAM` with `SAM.LOG1` changes nothing and warns nothing, because
   the log is older than the clean hive.
3. A truncated log still applies the valid entries that precede the damage and
   warns about the tail.
4. Parsing a hive with no logs behaves exactly as it does today.
5. `npm run typecheck` and `npm test` pass; no test weakened, skipped or
   deleted; `git diff --stat -- fixtures/` stays empty.

Committed fixtures cannot cover this — the hives that exercise replay are real
evidence and are not in the repository. Write the tests so they run against
paths supplied by an environment variable and skip cleanly when it is unset,
following the pattern already used for real-file tests elsewhere in this
codebase.

Run `npm run typecheck` and `npm test` at the end and report the real output.
