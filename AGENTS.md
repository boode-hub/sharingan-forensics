# Rules for agents working in this repo

Start with [MASTER_PROMPT.md](MASTER_PROMPT.md) for the current state, the
porting workflow and what comes next. Read [SPEC.md](SPEC.md) before writing
any parser. It defines the contract, the phases and the test requirements.
This file is the short version of what gets a change rejected in review.

## Hard rules

- **No network calls anywhere.** No `fetch`, `XMLHttpRequest`, `WebSocket`,
  `navigator.sendBeacon`, no remote fonts, no CDN scripts, no analytics. This is
  forensic software; evidence stays on the machine. Any network call fails review.
- **No new dependencies** unless you state in the summary what handwritten code
  it replaces and why the platform cannot do it. `DataView`, `TextDecoder`,
  `SubtleCrypto`, `DecompressionStream`, Web Workers and OPFS cover most needs.
- **Parsers never throw on bad data.** Call `ctx.warn(offset, message)` and keep
  going. Emit every record you recovered. A file that is 90% readable must
  produce 90% of its rows, not an error page.
- **Async generators only.** `parse` yields rows as it finds them. Never build a
  full array and return it — inputs reach multiple gigabytes.
- **Read via `reader.bytes(offset, length)`.** Never `await blob.arrayBuffer()`
  on the whole input.
- **Timestamps are `Date | null`.** Never a string, never `0`, never `new
  Date(0)` as a stand-in for missing. Use the helpers in `src/core/binary.ts`.

## Before you say you are done

Run both and paste the real output in your summary:

```
npm run typecheck && npm test
```

Do not claim a parser works because the code looks right. It works when a test
parses a fixture and matches the expected output. If you could not produce a
fixture, say so plainly in the summary rather than writing a test that asserts
nothing.

## Style

- Reuse what is in `src/core/` — `Cursor`, `filetime`, `guid`, `utf16`, `magic`
  already exist. Re-implementing them is the most common rejected change.
- Shell-item parsing belongs in `src/core/shellitem.ts` and is shared by LNK,
  Jump Lists and ShellBags. Do not fork it per parser.
- Boring code over clever code. No abstractions with one implementation, no
  config for a value that never changes, no scaffolding for a future phase.
- Comment the format quirks, not the syntax. `// fixup array replaces the last
  2 bytes of each 512-byte sector` is useful; `// loop over records` is not.
- Cite the format reference you worked from at the top of each parser file.

## What not to touch

`src/core/types.ts`, `src/core/registry.ts` and `src/core/binary.ts` are the
contract. If a parser genuinely needs a change there, make the change minimal,
keep every existing test passing, and call it out at the top of your summary.
