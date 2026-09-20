# Feedback on the EVTX BinXML decoder — review iteration 1

The port is working well. On a real 16 MB Windows Defender log it decodes
19,349 records with **zero warnings**, the chunk-header offset bug is fixed,
and the columns are right: eventId 1126, level `Warning`, provider
`Microsoft-Windows-Windows Defender`, channel
`Microsoft-Windows-Windows Defender/Operational`, computer `EG-NB-PF5Y9CBJ`.
18,888 of 19,349 payloads carry real values.

One defect remains, and it loses evidence.

## Defect: the record that DEFINES a template loses its own substitutions

461 records render an `<EventData>` whose `<Data>` elements are all **empty**:

```xml
<EventData><Data Name="Product Name"></Data><Data Name="Product Version"></Data>
<Data Name="ID"></Data><Data Name="Detection Time"></Data>...</EventData>
```

while other records of the *same event id* render correctly:

```xml
<EventData><Data Name="Product Name">Microsoft Defender Antivirus</Data>
<Data Name="Product Version">4.18.26080.3</Data>
<Data Name="Detection Time">2026-09-13T12:45:52.075Z</Data>...
```

So the template resolves — every `Data Name` is present and in the right order —
but the substituted **values** come back empty.

### Why this is a template-definition problem, not a template-lookup problem

The distribution says so:

- Event 1126: **200 empty against 15,197 correct**. Event 2010: 127 against
  1,889. The same template works far more often than it fails.
- The file is 16 MB, which is roughly 256 chunks, and there are ~200 failures
  for 1126 — about **one per chunk**.
- The specific failing record examined, record id **122608**, is the **first
  record in its chunk**.

That is the signature of the record that carries an **inline template
definition**. The first use of a template in a chunk defines it; later records
in that chunk reference the cached definition by offset and work correctly.

The likely cause is that after reading the template definition, the cursor is
left at the wrong place, so the substitution array that follows the definition
is read from the wrong offset — or its descriptor count is read as zero — and
every value comes out empty. The definition's own bytes must not be consumed as
substitution data.

Check this against `.refs/TemplateInstance.cs` and `.refs/TagBuilder.cs`, which
you already downloaded. In his implementation, look at how the template
definition's length is used to find where the substitution array begins, and
make sure the definition-carrying record follows exactly the same substitution
path as a record that merely references a cached template.

## Definition of done

1. On a real EVTX log, **zero records** render an `<EventData>` whose `Data`
   elements are all empty while the event genuinely has data. Concretely: for
   event 1126 in a Defender log, the count of empty-payload records drops from
   200 to 0.
2. The first record in a chunk decodes its values identically to later records
   using the same template.
3. `npm run typecheck` and `npm test` pass; no test weakened, skipped or
   deleted; `git diff --stat -- fixtures/` stays empty.
4. Add a regression test that decodes a record carrying an inline template
   definition and asserts its substituted values are non-empty.

Run `npm run typecheck` and `npm test` at the end and report the real output.
