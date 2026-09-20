# Task: complete the EVTX parser — full parity with EvtxECmd

`src/parsers/evtx.ts` currently reads only record framing: identifier, written
time, chunk. That is not usable for analysis. An analyst needs the event id,
the provider, the channel, the computer, the level and the payload — and all of
those live inside the BinXML blob this parser currently skips.

Read `AGENTS.md` and `SPEC.md` first. This is a forensics tool: **no shortcuts,
and nothing left unparsed.** Parity with EvtxECmd is the definition of done.

## PORT ERIC ZIMMERMAN'S CODE — do not invent a BinXML decoder

Download each file into `.refs/` inside this repository (gitignored) with
`curl`, then port it. Do **not** write outside the repository — that is blocked
and has already killed one task mid-port.

```bash
curl -sL -o .refs/TagBuilder.cs https://raw.githubusercontent.com/EricZimmerman/evtx/master/evtx/Tags/TagBuilder.cs
```

| What | File |
|---|---|
| The BinXML tag reader — the heart of it | `evtx/Tags/TagBuilder.cs` |
| Template definitions and instances | `evtx/Tags/Template.cs`, `evtx/Tags/TemplateInstance.cs` |
| Substitution arrays and every value type | `evtx/SubstitutionArrayEntry.cs` |
| Normal and conditional substitutions | `evtx/Tags/NormalSubstitution.cs` |
| Element and attribute tags | `evtx/Tags/OpenStartElementTag.cs`, `evtx/Tags/Attribute.cs` |
| Record assembly and the payload properties | `evtx/EventRecord.cs` |
| Chunk handling, including the template and string caches | `evtx/ChunkInfo.cs` |
| File walking | `evtx/EventLog.cs` |
| The event maps that name fields per event id | `evtx/EventLogMap.cs` |

`ChunkInfo.cs` matters more than it looks: BinXML templates and strings are
cached **per chunk** and referenced by offset, so a record cannot be decoded
without the chunk's caches. Port that structure rather than decoding records in
isolation.

## Fix first: the chunk header is read 8 bytes early

In the current `src/parsers/evtx.ts` the chunk cursor is created as
`new Cursor(chunk, 0)` and then reads four `u64`s before the `u32` fields. It
never skips the 8-byte `ElfChnk\0` signature, so every field is 8 bytes early:
`freeSpaceOffset` actually reads `headerSize`.

Verified on a real log: the raw bytes give `headerSize` 128,
`lastRecordOffset` 13016, `freeSpaceOffset` 13584, but the parser reported
`free space offset 128 is out of bounds`. It then fell back to the chunk end,
which happens to find the right records in a clean chunk but would walk into
slack and emit phantom records in a chunk that has any.

Start the cursor at offset 8.

## Required output columns — exact keys, one row per event record

```
recordId      num   event record identifier
writtenTime   date  the record's written time
eventId       num   from System/EventID
level         str   the NAME, e.g. Information, Warning, Error, Critical, Verbose
provider      str   System/Provider @Name
channel       str   System/Channel
computer      str   System/Computer
userId        str   System/Security @UserID (a SID), or null
processId     num   System/Execution @ProcessID, or null
threadId      num   System/Execution @ThreadID, or null
payload       str   the EventData / UserData rendered as compact JSON of
                    name/value pairs, so it is filterable and readable
xml           str   the full rendered BinXML, secondary: true
chunkNumber   num
offset        num   absolute byte offset of the record
```

Mark `xml` as `secondary: true` so it stays out of the default grid but is
still exported.

Where his event maps supply friendlier names for an event id, use them — that
is what makes EvtxECmd output readable rather than raw XML.

## Behaviour on bad data — this is the part that matters most

Never throw, and never silently drop an event.

- A record whose BinXML fails to decode must **still emit a row** carrying
  `recordId`, `writtenTime`, `chunkNumber` and `offset`, with the decoded
  columns null and a `ctx.warn()` naming the offset and the reason. Losing the
  payload must never lose the fact that the event existed.
- A corrupt chunk costs that chunk only; keep walking the others.
- Guard every template and string cache lookup against a bad offset, and guard
  template recursion with a depth limit — a malformed template that references
  itself must not hang the tab.

## Tests

The committed `fixtures/evtx/Synthetic.evtx` has deliberately opaque payloads,
so it still proves framing but not BinXML. Keep its existing assertions passing.

For BinXML, generate a fixture whose expected values you derive **from the
ported code's format rules, not from your own parser's output**, and document in
`fixtures/evtx/make.mjs` how each expected value was derived.

Also add:

- A record that fails BinXML decoding still yields a row with a warning.
- Truncation at several lengths: no throw, no hang.
- A template with a self-reference: no hang.

Finally run `npm run typecheck` and `npm test` and report the real output.
