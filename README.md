# Sharingan Forensics

Windows forensic artifact parsing in the browser. Drop in a `$I`, a Prefetch
file, a `.lnk`, a registry hive or an `.evtx`, and read it as a table.

**Nothing is uploaded.** There is no backend and no network call anywhere in the
shipped code — CI fails the build if one appears. Every byte is parsed in your
own tab, which is what makes it usable on evidence at all.

This is a browser replacement for the [Eric Zimmerman
toolset](https://ericzimmerman.github.io/). See [SPEC.md](SPEC.md) for the full
tool-by-tool coverage table and the phase plan.

## Status

**Live at <https://boode-hub.github.io/sharingan-forensics/>**

Early. The foundation, the app shell and the first parser are in; most of the
suite is not. The coverage table in SPEC.md is the honest list of what works.

| | |
|---|---|
| Recycle Bin (`$I`, `INFO2`) — RBCmd | working |
| Everything else | see SPEC.md |

## Running it

```bash
npm ci && npm run dev
```

```bash
npm run typecheck && npm test
```

## How it is built

Parsers are plain objects implementing the `Parser` contract in
[`src/core/types.ts`](src/core/types.ts) — an async generator that yields rows
and reports problems through `ctx.warn()` instead of throwing. Malformed
evidence is the normal case, so a parser that hits a corrupt record emits
everything it recovered and names what it could not. Parsing runs in a Web
Worker against a streaming `Reader`, so a multi-gigabyte `$MFT` never has to fit
in memory.

Test fixtures are **generated from the documented on-disk layout** by a
`make.mjs` beside each sample, deliberately written independently of the parser.
The fixture is the oracle: a parser that agrees with it is agreeing with the
format rather than with itself. CI regenerates the fixtures and fails if the
committed bytes drift.

Contributor rules are in [AGENTS.md](AGENTS.md).

## Licence

MIT. Not affiliated with or endorsed by Eric Zimmerman.
