# 4NSEC

Windows forensic artifact parsing in the browser. Drop in an event log, a
registry hive, a Prefetch file, a shortcut or a Recycle Bin record and read it
as a table you can search, filter and run Sigma rules against.

**Nothing is uploaded.** There is no backend and no network call anywhere in the
shipped code — CI fails the build if one appears. Every byte is parsed in your
own tab, which is what makes it usable on evidence at all.

It is a browser counterpart to the [Eric Zimmerman
toolset](https://ericzimmerman.github.io/), ported from his source where it is
published. See [SPEC.md](SPEC.md) for the tool-by-tool coverage table and the
phase plan.

## Status

**Live at <https://boode-hub.github.io/sharingan-forensics/>**

| Artifact | Counterpart | |
|---|---|---|
| Event logs (`.evtx`) | EvtxECmd | BinXML, all 468 of his event maps, hidden-record detection; XML matches Windows' own rendering |
| Registry hives | Registry Explorer | deleted key and value recovery, value slack, transaction log replay (open the `.LOG1`/`.LOG2` with the hive) |
| Amcache (`Amcache.hve`) | AmcacheParser | Windows 8 and Windows 10+ layouts, one tab per CSV he writes (file entries, programs, shortcuts, devices, drivers), deleted entries included |
| Shell bags | Shell Bags Explorer | from UsrClass.dat or NTUSER.DAT via **Read as** |
| Shimcache | AppCompatCacheParser | from a SYSTEM hive via **Read as**, XP to Windows 11 |
| Prefetch (`.pf`) | PECmd | versions 17 to 31, every file, directory and MFT reference |
| Shortcuts (`.lnk`) | LECmd | target ID list, tracker block, every extra data block |
| Recycle Bin (`$I`, `INFO2`) | RBCmd | |
| Everything else | | see SPEC.md |

## Finding things

The search box and every column filter take the same language:

```text
powershell                        any column contains "powershell"
4624 OR 4625                      either
admin AND -svchost                both; "-" excludes (also NOT and !)
(4624 OR 4625) NOT system         grouping
TargetUserName=admin              a field inside the event's payload, exactly
CommandLine contains "-enc"       also startswith and endswith; quote a leading dash
LogonType>=10                     numbers compare as numbers
TimeCreated>=2024-01-01T09:00     dates compare as instants, in UTC
Image:*\powershell.exe            * and ? are wildcards
```

Terms next to each other are ANDed. A field is a column (by key or label) or a
field inside the event XML, such as `TargetUserName` or `CommandLine`.

**Save filter** keeps the search, the column filters and any running Sigma rule
under a name, for that kind of artifact. Saved filters live in this browser.

## Sigma

Open **Sigma**, paste a rule (or open a `.yml`) and press **Run rule**. The rule
is evaluated here, against the rows in the tab, and its matches filter the grid
alongside the search and the column filters. It stays running as you move
between artifacts, so one rule can be run across a whole collection of logs.

It supports every value modifier in the specification except `expand`,
keywords, null values, wildcards and their escapes, `1 of` / `all of` with
patterns, and logsource scoping for the Windows services and Sysmon categories,
including `process_creation` rules against Security 4688 with its field names.
Aggregations and timeframes need events correlated over time; a rule that uses
them is run without them, and the panel says so.

Checked against SigmaHQ itself: all 3,783 rules in the repository compile, and
all 459 of its regression cases — real `.evtx` files with the number of events
each rule must match — match exactly, parsed by this tool's own EVTX parser.
`SIGMA_REPO=path/to/sigma npx vitest run src/ui/sigma.regression.test.ts` runs
that suite.

## Layout and theme

The gear in the top right sets the theme colour and where the selected row's
details sit: underneath the table, or beside it on the left or right. Event XML
and payloads in the details are laid out one element per line.

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
Worker against a streaming `Reader`, so a multi-gigabyte file never has to fit
in memory at once.

Test fixtures are either **generated from the documented on-disk layout** by a
`make.mjs` beside each sample, written independently of the parser, or taken
from the MIT-licensed test corpora of Eric Zimmerman's own libraries with his
published expectations asserted against them. The fixture is the oracle: a
parser that agrees with it is agreeing with the format rather than with itself.
CI regenerates the generated fixtures and fails if the committed bytes drift.

Contributor rules are in [AGENTS.md](AGENTS.md).

## Credits and licences

MIT. Not affiliated with or endorsed by Eric Zimmerman or SigmaHQ.

The logo and theme come from the Phishing Email Analyzer. Inter and JetBrains
Mono are used under the SIL Open Font License 1.1; the licence texts are in
[`src/assets/fonts/`](src/assets/fonts/).
