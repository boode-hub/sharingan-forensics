import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { bufReader } from '../core/reader';
import { run } from '../core/registry';
import { evtx } from './evtx';
import {
  TOKEN_START_STREAM,
  TOKEN_TEMPLATE_INSTANCE,
  TOKEN_EOF,
  TOKEN_OPEN_START_ELEMENT,
  TOKEN_CLOSE_START_ELEMENT,
  TOKEN_CLOSE_EMPTY_ELEMENT,
  TOKEN_END_ELEMENT,
  TOKEN_OPEN_START_ELEMENT_ATTR,
  TOKEN_ATTRIBUTE,
  TOKEN_ATTRIBUTE_MORE,
  TOKEN_NORMAL_SUBSTITUTION,
} from './evtx/binxml';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = join(__dirname, '../../fixtures/evtx');

function loadFixture(name: string): Uint8Array {
  return new Uint8Array(readFileSync(join(FIXTURE_DIR, name)));
}

function loadExpected(): Record<string, unknown[]> {
  const raw = readFileSync(join(FIXTURE_DIR, 'expected.json'), 'utf-8');
  return JSON.parse(raw);
}

function normalizeRows(rows: Record<string, unknown>[]): Record<string, unknown>[] {
  return rows.map((r) => {
    const out: Record<string, unknown> = { ...r };
    if (out.writtenTime instanceof Date) {
      out.writtenTime = out.writtenTime.toISOString();
    }
    return out;
  });
}

class BufferWriter {
  buf = new Uint8Array(4096);
  pos = 0;

  ensure(n: number) {
    if (this.pos + n > this.buf.length) {
      const next = new Uint8Array(Math.max(this.buf.length * 2, this.pos + n));
      next.set(this.buf);
      this.buf = next;
    }
  }

  u8(v: number): this {
    this.ensure(1);
    this.buf[this.pos++] = v;
    return this;
  }
  u16(v: number): this {
    this.ensure(2);
    new DataView(this.buf.buffer, this.buf.byteOffset).setUint16(this.pos, v, true);
    this.pos += 2;
    return this;
  }
  i16(v: number): this {
    this.ensure(2);
    new DataView(this.buf.buffer, this.buf.byteOffset).setInt16(this.pos, v, true);
    this.pos += 2;
    return this;
  }
  u32(v: number): this {
    this.ensure(4);
    new DataView(this.buf.buffer, this.buf.byteOffset).setUint32(this.pos, v, true);
    this.pos += 4;
    return this;
  }
  i32(v: number): this {
    this.ensure(4);
    new DataView(this.buf.buffer, this.buf.byteOffset).setInt32(this.pos, v, true);
    this.pos += 4;
    return this;
  }
  bytes(b: Uint8Array): this {
    this.ensure(b.length);
    this.buf.set(b, this.pos);
    this.pos += b.length;
    return this;
  }
  utf16(str: string): this {
    for (let i = 0; i < str.length; i++) {
      this.u16(str.charCodeAt(i));
    }
    return this;
  }
  result(): Uint8Array {
    return this.buf.subarray(0, this.pos);
  }
}

function makeStringEntry(str: string): Uint8Array {
  const w = new BufferWriter();
  w.u32(0); // next offset in bucket
  w.u16(0x1234); // hash
  w.u16(str.length); // character length
  w.utf16(str);
  w.u16(0); // null terminator
  return w.result();
}

/**
 * Builds a valid in-memory .evtx buffer with a single chunk containing given records.
 */
function makeSyntheticEvtxFile(records: Uint8Array[], stringEntries: { offset: number; str: string }[] = []): Uint8Array {
  const CHUNK_SIZE = 65536;
  const RECORDS_START = 512;
  const chunk = new Uint8Array(CHUNK_SIZE);
  const dv = new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength);

  // 'ElfChnk\0'
  const chunkSig = 'ElfChnk\0';
  for (let i = 0; i < chunkSig.length; i++) chunk[i] = chunkSig.charCodeAt(i);

  dv.setBigInt64(8, 1n, true);
  dv.setBigInt64(16, BigInt(records.length), true);
  dv.setBigInt64(24, 1n, true);
  dv.setBigInt64(32, BigInt(records.length), true);
  dv.setUint32(40, 128, true);

  // Write string entries in chunk
  for (const se of stringEntries) {
    const entryBytes = makeStringEntry(se.str);
    chunk.set(entryBytes, se.offset);
  }

  let pos = RECORDS_START;
  let lastPos = RECORDS_START;
  for (const rec of records) {
    lastPos = pos;
    chunk.set(rec, pos);
    pos += rec.length;
  }

  dv.setUint32(44, lastPos, true);
  dv.setUint32(48, pos, true);

  // File header 4096 bytes
  const HEADER_SIZE = 4096;
  const file = new Uint8Array(HEADER_SIZE + CHUNK_SIZE);
  const fileDv = new DataView(file.buffer, file.byteOffset, file.byteLength);

  const fileSig = 'ElfFile\0';
  for (let i = 0; i < fileSig.length; i++) file[i] = fileSig.charCodeAt(i);

  fileDv.setBigInt64(8, 0n, true);
  fileDv.setBigInt64(16, 0n, true);
  fileDv.setBigInt64(24, BigInt(records.length + 1), true);
  fileDv.setUint32(32, 128, true);
  fileDv.setUint16(36, 1, true);
  fileDv.setUint16(38, 3, true);
  fileDv.setUint16(40, 4096, true);
  fileDv.setUint16(42, 1, true);

  file.set(chunk, HEADER_SIZE);
  return file;
}

function makeRecord(id: number, payload: Uint8Array): Uint8Array {
  const size = 24 + payload.length + 4;
  const rec = new Uint8Array(size);
  const dv = new DataView(rec.buffer, rec.byteOffset, rec.byteLength);
  dv.setUint32(0, 0x00002a2a, true);
  dv.setUint32(4, size, true);
  dv.setBigInt64(8, BigInt(id), true);
  // 2024-05-01 10:00:00 UTC in FILETIME
  dv.setBigInt64(16, 133590024000000000n, true);
  rec.set(payload, 24);
  dv.setUint32(size - 4, size, true);
  return rec;
}

describe('evtx parser', () => {
  const expected = loadExpected();

  for (const [name, expRows] of Object.entries(expected)) {
    it(`parses ${name} correctly`, async () => {
      const buf = loadFixture(name);
      const reader = bufReader(buf, name);
      const outcome = await run(evtx, reader);
      const got = normalizeRows(outcome.rows);
      expect(got).toMatchObject(expRows);
    });
  }

  it('emits rows with null decoded columns and warnings when BinXML fails', async () => {
    const buf = loadFixture('Synthetic.evtx');
    const reader = bufReader(buf, 'Synthetic.evtx');
    const outcome = await run(evtx, reader);

    expect(outcome.rows.length).toBe(3);
    expect(outcome.warnings.length).toBeGreaterThan(0);

    const first = outcome.rows[0];
    expect(first.recordNumber).toBe(1);
    expect(first.chunkNumber).toBe(0);
    expect(first.offset).toBe(4608);
    expect(first.eventId).toBeNull();
    expect(first.level).toBeNull();
    expect(first.provider).toBeNull();
    expect(first.channel).toBeNull();
    expect(first.computer).toBeNull();
    expect(first.userId).toBeNull();
    expect(first.processId).toBeNull();
    expect(first.threadId).toBeNull();
    expect(first.payload).toBeNull();
    expect(first.xml).toBeNull();
  });

  describe('truncation tests', () => {
    it('never throws or hangs across several truncation points', async () => {
      const buf = loadFixture('Synthetic.evtx');
      const lengths = [100, 4096, 5000, Math.floor(buf.length / 2)];
      for (const len of lengths) {
        const truncated = buf.subarray(0, len);
        const reader = bufReader(truncated, 'Synthetic.evtx');
        const outcome = await run(evtx, reader);
        expect(outcome.rows).toBeDefined();
      }
    });

    it('produces zero rows and a warning with no chunks at all', async () => {
      const buf = loadFixture('Synthetic.evtx');
      const truncated = buf.subarray(0, 4096);
      const reader = bufReader(truncated, 'Synthetic.evtx');
      const outcome = await run(evtx, reader);
      expect(outcome.rows.length).toBe(0);
      expect(outcome.warnings.length).toBeGreaterThan(0);
    });
  });

  describe('garbage test', () => {
    it('does not throw or hang on random bytes with ElfFile\\0 at offset 0', async () => {
      const buf = new Uint8Array(70000);
      for (let i = 0; i < buf.length; i += 65536) {
        crypto.getRandomValues(buf.subarray(i, Math.min(i + 65536, buf.length)));
      }
      const sig = 'ElfFile\0';
      for (let i = 0; i < sig.length; i++) buf[i] = sig.charCodeAt(i);
      const reader = bufReader(buf, 'garbage.evtx');
      const outcome = await run(evtx, reader);
      expect(outcome.rows).toBeDefined();
    });
  });

  describe('full BinXML decoding and event maps', () => {
    it('fully decodes BinXML with per-chunk template, string cache and event map', async () => {
      // Setup string table entries in chunk
      const strings = [
        { offset: 1000, str: 'Event' },
        { offset: 1050, str: 'System' },
        { offset: 1100, str: 'Provider' },
        { offset: 1150, str: 'Name' },
        { offset: 1200, str: 'EventID' },
        { offset: 1250, str: 'Level' },
        { offset: 1300, str: 'Channel' },
        { offset: 1350, str: 'Computer' },
        { offset: 1400, str: 'Security' },
        { offset: 1450, str: 'UserID' },
        { offset: 1500, str: 'Execution' },
        { offset: 1550, str: 'ProcessID' },
        { offset: 1600, str: 'ThreadID' },
        { offset: 1650, str: 'EventData' },
        { offset: 1700, str: 'Data' },
        { offset: 1750, str: 'TargetUserName' },
      ];

      // Build template XML:
      // <Event>
      //   <System>
      //     <Provider Name="%0"/>
      //     <EventID>%1</EventID>
      //     <Level>%2</Level>
      //     <Channel>%3</Channel>
      //     <Computer>%4</Computer>
      //     <Security UserID="%5"/>
      //     <Execution ProcessID="%6" ThreadID="%7"/>
      //   </System>
      //   <EventData>
      //     <Data Name="%8">%9</Data>
      //   </EventData>
      // </Event>
      const tw = new BufferWriter();
      tw.u8(TOKEN_START_STREAM).u8(1).u8(1).u8(0);

      // <Event>
      tw.u8(TOKEN_OPEN_START_ELEMENT).i16(-1);
      const eventSizePos = tw.pos;
      tw.u32(0).u32(1000).u8(TOKEN_CLOSE_START_ELEMENT);

      // <System>
      tw.u8(TOKEN_OPEN_START_ELEMENT).i16(-1);
      const sysSizePos = tw.pos;
      tw.u32(0).u32(1050).u8(TOKEN_CLOSE_START_ELEMENT);

      // <Provider Name="%0"/>
      tw.u8(TOKEN_OPEN_START_ELEMENT_ATTR).i16(-1);
      const provSizePos = tw.pos;
      tw.u32(0).u32(1100);
      const provAttrPos = tw.pos;
      tw.u32(0).u8(TOKEN_ATTRIBUTE).u32(1150).u8(TOKEN_NORMAL_SUBSTITUTION).u16(0).u8(1);
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(provAttrPos, tw.pos - (provAttrPos + 4), true);
      tw.u8(TOKEN_CLOSE_EMPTY_ELEMENT);
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(provSizePos, tw.pos - (provSizePos + 4), true);

      // <EventID>%1</EventID>
      tw.u8(TOKEN_OPEN_START_ELEMENT).i16(-1);
      const idSizePos = tw.pos;
      tw.u32(0).u32(1200).u8(TOKEN_CLOSE_START_ELEMENT).u8(TOKEN_NORMAL_SUBSTITUTION).u16(1).u8(8).u8(TOKEN_END_ELEMENT);
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(idSizePos, tw.pos - (idSizePos + 4), true);

      // <Level>%2</Level>
      tw.u8(TOKEN_OPEN_START_ELEMENT).i16(-1);
      const lvlSizePos = tw.pos;
      tw.u32(0).u32(1250).u8(TOKEN_CLOSE_START_ELEMENT).u8(TOKEN_NORMAL_SUBSTITUTION).u16(2).u8(4).u8(TOKEN_END_ELEMENT);
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(lvlSizePos, tw.pos - (lvlSizePos + 4), true);

      // <Channel>%3</Channel>
      tw.u8(TOKEN_OPEN_START_ELEMENT).i16(-1);
      const chSizePos = tw.pos;
      tw.u32(0).u32(1300).u8(TOKEN_CLOSE_START_ELEMENT).u8(TOKEN_NORMAL_SUBSTITUTION).u16(3).u8(1).u8(TOKEN_END_ELEMENT);
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(chSizePos, tw.pos - (chSizePos + 4), true);

      // <Computer>%4</Computer>
      tw.u8(TOKEN_OPEN_START_ELEMENT).i16(-1);
      const cmpSizePos = tw.pos;
      tw.u32(0).u32(1350).u8(TOKEN_CLOSE_START_ELEMENT).u8(TOKEN_NORMAL_SUBSTITUTION).u16(4).u8(1).u8(TOKEN_END_ELEMENT);
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(cmpSizePos, tw.pos - (cmpSizePos + 4), true);

      // <Security UserID="%5"/>
      tw.u8(TOKEN_OPEN_START_ELEMENT_ATTR).i16(-1);
      const secSizePos = tw.pos;
      tw.u32(0).u32(1400);
      const secAttrPos = tw.pos;
      tw.u32(0).u8(TOKEN_ATTRIBUTE).u32(1450).u8(TOKEN_NORMAL_SUBSTITUTION).u16(5).u8(1);
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(secAttrPos, tw.pos - (secAttrPos + 4), true);
      tw.u8(TOKEN_CLOSE_EMPTY_ELEMENT);
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(secSizePos, tw.pos - (secSizePos + 4), true);

      // <Execution ProcessID="%6" ThreadID="%7"/>
      tw.u8(TOKEN_OPEN_START_ELEMENT_ATTR).i16(-1);
      const execSizePos = tw.pos;
      tw.u32(0).u32(1500);
      const execAttrPos = tw.pos;
      tw.u32(0);
      tw.u8(TOKEN_ATTRIBUTE_MORE).u32(1550).u8(TOKEN_NORMAL_SUBSTITUTION).u16(6).u8(8);
      tw.u8(TOKEN_ATTRIBUTE).u32(1600).u8(TOKEN_NORMAL_SUBSTITUTION).u16(7).u8(8);
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(execAttrPos, tw.pos - (execAttrPos + 4), true);
      tw.u8(TOKEN_CLOSE_EMPTY_ELEMENT);
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(execSizePos, tw.pos - (execSizePos + 4), true);

      tw.u8(TOKEN_END_ELEMENT); // </System>
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(sysSizePos, tw.pos - (sysSizePos + 4), true);

      // <EventData>
      tw.u8(TOKEN_OPEN_START_ELEMENT).i16(-1);
      const datSizePos = tw.pos;
      tw.u32(0).u32(1650).u8(TOKEN_CLOSE_START_ELEMENT);

      // <Data Name="%8">%9</Data>
      tw.u8(TOKEN_OPEN_START_ELEMENT_ATTR).i16(-1);
      const dSizePos = tw.pos;
      tw.u32(0).u32(1700);
      const dAttrPos = tw.pos;
      tw.u32(0).u8(TOKEN_ATTRIBUTE).u32(1150).u8(TOKEN_NORMAL_SUBSTITUTION).u16(8).u8(1);
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(dAttrPos, tw.pos - (dAttrPos + 4), true);
      tw.u8(TOKEN_CLOSE_START_ELEMENT).u8(TOKEN_NORMAL_SUBSTITUTION).u16(9).u8(1).u8(TOKEN_END_ELEMENT);
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(dSizePos, tw.pos - (dSizePos + 4), true);

      tw.u8(TOKEN_END_ELEMENT); // </EventData>
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(datSizePos, tw.pos - (datSizePos + 4), true);

      tw.u8(TOKEN_END_ELEMENT); // </Event>
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(eventSizePos, tw.pos - (eventSizePos + 4), true);
      tw.u8(TOKEN_EOF);

      const templateXml = tw.result();

      // Build payload for Record 1 (at chunk offset 512, payload starts at 536)
      const pw = new BufferWriter();
      pw.u8(TOKEN_START_STREAM).u8(1).u8(1).u8(0);

      // TemplateInstance (inline template definition)
      pw.u8(TOKEN_TEMPLATE_INSTANCE);
      pw.u8(1); // version
      pw.i32(1); // templateId
      const templateOffset = 536 + pw.pos; // 542
      pw.u32(templateOffset);
      pw.i32(0); // nextTemplateOffset
      pw.bytes(new Uint8Array(16)); // GUID
      pw.i32(templateXml.length);
      pw.bytes(templateXml);

      // Substitutions:
      // 0: Provider: "Microsoft-Windows-Security-Auditing"
      // 1: EventID: 4624
      // 2: Level: 0
      // 3: Channel: "Security"
      // 4: Computer: "DC01.corp.local"
      // 5: UserID: "S-1-5-18"
      // 6: ProcessID: 776
      // 7: ThreadID: 780
      // 8: "TargetUserName"
      // 9: "Administrator"
      const subs = [
        { type: 1, b: Buffer.from('Microsoft-Windows-Security-Auditing\0', 'utf16le') },
        { type: 8, b: (() => { const b = Buffer.alloc(4); b.writeUInt32LE(4624); return b; })() },
        { type: 4, b: Buffer.from([0]) },
        { type: 1, b: Buffer.from('Security\0', 'utf16le') },
        { type: 1, b: Buffer.from('DC01.corp.local\0', 'utf16le') },
        { type: 1, b: Buffer.from('S-1-5-18\0', 'utf16le') },
        { type: 8, b: (() => { const b = Buffer.alloc(4); b.writeUInt32LE(776); return b; })() },
        { type: 8, b: (() => { const b = Buffer.alloc(4); b.writeUInt32LE(780); return b; })() },
        { type: 1, b: Buffer.from('TargetUserName\0', 'utf16le') },
        { type: 1, b: Buffer.from('Administrator\0', 'utf16le') },
      ];

      pw.u32(subs.length);
      for (const s of subs) {
        pw.u16(s.b.length);
        pw.u16(s.type);
      }
      for (const s of subs) {
        pw.bytes(s.b);
      }
      pw.u8(TOKEN_EOF);

      const recordBytes = makeRecord(1, pw.result());
      const evtxBytes = makeSyntheticEvtxFile([recordBytes], strings);

      const reader = bufReader(evtxBytes, 'test-binxml.evtx');
      const outcome = await run(evtx, reader);

      expect(outcome.rows.length).toBe(1);
      const row = outcome.rows[0];

      expect(row.recordNumber).toBe(1);
      expect(row.eventId).toBe(4624);
      expect(row.level).toBe('Information');
      expect(row.provider).toBe('Microsoft-Windows-Security-Auditing');
      expect(row.channel).toBe('Security');
      expect(row.computer).toBe('DC01.corp.local');
      expect(row.userId).toBe('S-1-5-18');
      expect(row.processId).toBe(776);
      expect(row.threadId).toBe(780);

      // MapDescription is its own column, as it is in EvtxECmd's output, so an
      // analyst can filter on it instead of grepping a JSON blob.
      expect(row.mapDescription).toBe('Successful logon');
      expect(row.sourceFile).toBe('test-binxml.evtx');

      // Payload is the EventData element verbatim, which is what EvtxECmd puts
      // in its own Payload column.
      expect(row.payload).toContain('<Data Name="TargetUserName">Administrator</Data>');
      expect(row.payload).toMatch(/^<EventData/);

      // Verify xml column is populated
      expect(typeof row.xml).toBe('string');
      expect(row.xml).toContain('<EventID>4624</EventID>');
      expect(row.xml).toContain('<Computer>DC01.corp.local</Computer>');
    });
  });

  describe('template self-reference recursion guard', () => {
    it('does not hang when template definition has self-reference', async () => {
      // Build a record pointing to a template that references itself via BinXmlType recursion
      const tw = new BufferWriter();
      tw.u8(TOKEN_START_STREAM).u8(1).u8(1).u8(0);
      tw.u8(TOKEN_OPEN_START_ELEMENT).i16(-1);
      const sPos = tw.pos;
      tw.u32(0).u32(1000).u8(TOKEN_CLOSE_START_ELEMENT);
      // Optional substitution pointing to BinXmlType
      tw.u8(TOKEN_NORMAL_SUBSTITUTION).u16(0).u8(0x21); // BinXmlType
      tw.u8(TOKEN_END_ELEMENT);
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(sPos, tw.pos - (sPos + 4), true);
      tw.u8(TOKEN_EOF);
      const templateXml = tw.result();

      // Substitution value contains nested TemplateInstance referencing the same template
      const nestedPayload = new BufferWriter();
      nestedPayload.u8(TOKEN_START_STREAM).u8(1).u8(1).u8(0);
      nestedPayload.u8(TOKEN_TEMPLATE_INSTANCE);
      nestedPayload.u8(1).i32(1).u32(542); // points back to templateOffset 542
      nestedPayload.u32(0); // 0 subs
      nestedPayload.u8(TOKEN_EOF);

      const pw = new BufferWriter();
      pw.u8(TOKEN_START_STREAM).u8(1).u8(1).u8(0);
      pw.u8(TOKEN_TEMPLATE_INSTANCE);
      pw.u8(1).i32(1).u32(542);
      pw.i32(0); // nextTemplateOffset
      pw.bytes(new Uint8Array(16));
      pw.i32(templateXml.length);
      pw.bytes(templateXml);

      // 1 sub of type BinXmlType
      pw.u32(1);
      pw.u16(nestedPayload.pos).u16(0x21);
      pw.bytes(nestedPayload.result());
      pw.u8(TOKEN_EOF);

      const recordBytes = makeRecord(1, pw.result());
      const evtxBytes = makeSyntheticEvtxFile([recordBytes], [{ offset: 1000, str: 'Recursive' }]);

      const reader = bufReader(evtxBytes, 'recursive.evtx');
      const outcome = await run(evtx, reader);

      // Must complete promptly without hanging
      expect(outcome.rows.length).toBe(1);
    });
  });

  describe('corrupt chunk recovery', () => {
    it('skips a corrupt chunk and parses the clean subsequent chunk', async () => {
      // 2 chunks: Chunk 0 has bad signature, Chunk 1 is valid
      const CHUNK_SIZE = 65536;
      const HEADER_SIZE = 4096;
      const file = new Uint8Array(HEADER_SIZE + CHUNK_SIZE * 2);
      const fileDv = new DataView(file.buffer, file.byteOffset, file.byteLength);

      const fileSig = 'ElfFile\0';
      for (let i = 0; i < fileSig.length; i++) file[i] = fileSig.charCodeAt(i);
      fileDv.setBigInt64(8, 0n, true);
      fileDv.setBigInt64(16, 1n, true);
      fileDv.setBigInt64(24, 2n, true);
      fileDv.setUint32(32, 128, true);
      fileDv.setUint16(36, 1, true);
      fileDv.setUint16(38, 3, true);
      fileDv.setUint16(40, 4096, true);
      fileDv.setUint16(42, 2, true); // 2 chunks

      // Chunk 0: bad signature
      const badSig = 'BadChnk\0';
      for (let i = 0; i < badSig.length; i++) file[HEADER_SIZE + i] = badSig.charCodeAt(i);

      // Chunk 1: clean chunk with 1 record
      const cleanChunk = new Uint8Array(CHUNK_SIZE);
      const cSig = 'ElfChnk\0';
      for (let i = 0; i < cSig.length; i++) cleanChunk[i] = cSig.charCodeAt(i);
      const cDv = new DataView(cleanChunk.buffer, cleanChunk.byteOffset, cleanChunk.byteLength);
      cDv.setBigInt64(8, 2n, true);
      cDv.setBigInt64(16, 2n, true);
      cDv.setBigInt64(24, 2n, true);
      cDv.setBigInt64(32, 2n, true);
      cDv.setUint32(40, 128, true);

      // Record at 512
      const rec = makeRecord(2, new Uint8Array([0x0f, 0x01, 0x01, 0x00, 0x45, 0x01, 0x02, 0x00, 0x41, 0x00]));
      cleanChunk.set(rec, 512);
      cDv.setUint32(44, 512, true);
      cDv.setUint32(48, 512 + rec.length, true);

      file.set(cleanChunk, HEADER_SIZE + CHUNK_SIZE);

      const reader = bufReader(file, 'multi-chunk.evtx');
      const outcome = await run(evtx, reader);

      // Chunk 0 yielded warning, Chunk 1 yielded record 2
      expect(outcome.warnings.length).toBeGreaterThan(0);
      expect(outcome.rows.length).toBe(1);
      expect(outcome.rows[0].recordNumber).toBe(2);
      expect(outcome.rows[0].chunkNumber).toBe(1);
    });
  });

  describe('inline template definition substitutions (regression)', () => {
    it('decodes substituted values for record defining inline template and subsequent record reusing it', async () => {
      const strings = [
        { offset: 3000, str: 'Event' },
        { offset: 3050, str: 'System' },
        { offset: 3100, str: 'Provider' },
        { offset: 3150, str: 'Name' },
        { offset: 3200, str: 'EventID' },
        { offset: 3250, str: 'EventData' },
        { offset: 3300, str: 'Data' },
      ];

      // Top-level template: <Event><System><Provider Name="%0"/><EventID>%1</EventID></System>%2</Event>
      const tw = new BufferWriter();
      tw.u8(TOKEN_START_STREAM).u8(1).u8(1).u8(0);
      tw.u8(TOKEN_OPEN_START_ELEMENT).i16(-1);
      const eventSizePos = tw.pos;
      tw.u32(0).u32(3000).u8(TOKEN_CLOSE_START_ELEMENT);

      // <System>
      tw.u8(TOKEN_OPEN_START_ELEMENT).i16(-1);
      const sysSizePos = tw.pos;
      tw.u32(0).u32(3050).u8(TOKEN_CLOSE_START_ELEMENT);

      // <Provider Name="%0"/>
      tw.u8(TOKEN_OPEN_START_ELEMENT_ATTR).i16(-1);
      const provSizePos = tw.pos;
      tw.u32(0).u32(3100);
      const provAttrPos = tw.pos;
      tw.u32(0).u8(TOKEN_ATTRIBUTE).u32(3150).u8(TOKEN_NORMAL_SUBSTITUTION).u16(0).u8(1);
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(provAttrPos, tw.pos - (provAttrPos + 4), true);
      tw.u8(TOKEN_CLOSE_EMPTY_ELEMENT);
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(provSizePos, tw.pos - (provSizePos + 4), true);

      // <EventID>%1</EventID>
      tw.u8(TOKEN_OPEN_START_ELEMENT).i16(-1);
      const idSizePos = tw.pos;
      tw.u32(0).u32(3200).u8(TOKEN_CLOSE_START_ELEMENT).u8(TOKEN_NORMAL_SUBSTITUTION).u16(1).u8(8).u8(TOKEN_END_ELEMENT);
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(idSizePos, tw.pos - (idSizePos + 4), true);

      tw.u8(TOKEN_END_ELEMENT); // </System>
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(sysSizePos, tw.pos - (sysSizePos + 4), true);

      // Sub 2: BinXmlType (<EventData>)
      tw.u8(TOKEN_NORMAL_SUBSTITUTION).u16(2).u8(0x21);

      tw.u8(TOKEN_END_ELEMENT); // </Event>
      new DataView(tw.buf.buffer, tw.buf.byteOffset).setUint32(eventSizePos, tw.pos - (eventSizePos + 4), true);
      tw.u8(TOKEN_EOF);
      const topTemplateXml = tw.result();

      // Nested template for EventData: <EventData><Data Name="%0">%1</Data></EventData>
      const edw = new BufferWriter();
      edw.u8(TOKEN_START_STREAM).u8(1).u8(1).u8(0);
      edw.u8(TOKEN_OPEN_START_ELEMENT).i16(-1);
      const edSizePos = edw.pos;
      edw.u32(0).u32(3250).u8(TOKEN_CLOSE_START_ELEMENT);

      // <Data Name="%0">%1</Data>
      edw.u8(TOKEN_OPEN_START_ELEMENT_ATTR).i16(-1);
      const dSizePos = edw.pos;
      edw.u32(0).u32(3300);
      const dAttrPos = edw.pos;
      edw.u32(0).u8(TOKEN_ATTRIBUTE).u32(3150).u8(TOKEN_NORMAL_SUBSTITUTION).u16(0).u8(1);
      new DataView(edw.buf.buffer, edw.buf.byteOffset).setUint32(dAttrPos, edw.pos - (dAttrPos + 4), true);
      edw.u8(TOKEN_CLOSE_START_ELEMENT).u8(TOKEN_NORMAL_SUBSTITUTION).u16(1).u8(1).u8(TOKEN_END_ELEMENT);
      new DataView(edw.buf.buffer, edw.buf.byteOffset).setUint32(dSizePos, edw.pos - (dSizePos + 4), true);

      edw.u8(TOKEN_END_ELEMENT); // </EventData>
      new DataView(edw.buf.buffer, edw.buf.byteOffset).setUint32(edSizePos, edw.pos - (edSizePos + 4), true);
      edw.u8(TOKEN_EOF);
      const eventDataTemplateXml = edw.result();

      // Construct Record 1 (carries inline template definitions)
      const pw1 = new BufferWriter();
      pw1.u8(TOKEN_START_STREAM).u8(1).u8(1).u8(0);
      pw1.u8(TOKEN_TEMPLATE_INSTANCE);
      pw1.u8(1).i32(1);
      const topTemplateOffset = 536 + pw1.pos;
      pw1.u32(topTemplateOffset);
      pw1.i32(0);
      pw1.bytes(new Uint8Array(16));
      pw1.i32(topTemplateXml.length);
      pw1.bytes(topTemplateXml);

      const provBytes = Buffer.from('Microsoft-Windows-Windows Defender\0', 'utf16le');
      const idBytes = Buffer.alloc(4);
      idBytes.writeUInt32LE(1126);

      // Build nested EventData payload for Record 1 (INLINE template definition)
      const nested1StartInPw1 = pw1.pos + 4 + 12 + provBytes.length + idBytes.length;
      const eventDataTemplateOffset = 536 + nested1StartInPw1 + 10;

      const nested1 = new BufferWriter();
      nested1.u8(TOKEN_START_STREAM).u8(1).u8(1).u8(0);
      nested1.u8(TOKEN_TEMPLATE_INSTANCE);
      nested1.u8(1).i32(2);
      nested1.u32(eventDataTemplateOffset);
      nested1.i32(0);
      nested1.bytes(new Uint8Array(16));
      nested1.i32(eventDataTemplateXml.length);
      nested1.bytes(eventDataTemplateXml);

      const attrValBytes = Buffer.from('Product Name\0', 'utf16le');
      const dataValBytes = Buffer.from('Microsoft Defender Antivirus\0', 'utf16le');
      nested1.u32(2);
      nested1.u16(attrValBytes.length).u16(1);
      nested1.u16(dataValBytes.length).u16(1);
      nested1.bytes(attrValBytes);
      nested1.bytes(dataValBytes);
      nested1.u8(TOKEN_EOF);

      const nested1Bytes = nested1.result();

      pw1.u32(3);
      pw1.u16(provBytes.length).u16(1);
      pw1.u16(idBytes.length).u16(8);
      pw1.u16(nested1Bytes.length).u16(0x21);
      pw1.bytes(provBytes);
      pw1.bytes(idBytes);
      pw1.bytes(nested1Bytes);
      pw1.u8(TOKEN_EOF);

      const rec1 = makeRecord(1, pw1.result());

      // Record 2: references cached top-level template and cached nested template
      const pw2 = new BufferWriter();
      pw2.u8(TOKEN_START_STREAM).u8(1).u8(1).u8(0);
      pw2.u8(TOKEN_TEMPLATE_INSTANCE);
      pw2.u8(1).i32(1).u32(topTemplateOffset);

      const nested2 = new BufferWriter();
      nested2.u8(TOKEN_START_STREAM).u8(1).u8(1).u8(0);
      nested2.u8(TOKEN_TEMPLATE_INSTANCE);
      nested2.u8(1).i32(2).u32(eventDataTemplateOffset);

      const dataVal2Bytes = Buffer.from('Microsoft Defender Antivirus Updated\0', 'utf16le');
      nested2.u32(2);
      nested2.u16(attrValBytes.length).u16(1);
      nested2.u16(dataVal2Bytes.length).u16(1);
      nested2.bytes(attrValBytes);
      nested2.bytes(dataVal2Bytes);
      nested2.u8(TOKEN_EOF);

      const nested2Bytes = nested2.result();

      pw2.u32(3);
      pw2.u16(provBytes.length).u16(1);
      pw2.u16(idBytes.length).u16(8);
      pw2.u16(nested2Bytes.length).u16(0x21);
      pw2.bytes(provBytes);
      pw2.bytes(idBytes);
      pw2.bytes(nested2Bytes);
      pw2.u8(TOKEN_EOF);

      const rec2 = makeRecord(2, pw2.result());

      const evtxBytes = makeSyntheticEvtxFile([rec1, rec2], strings);
      const reader = bufReader(evtxBytes, 'regression-inline-template.evtx');
      const outcome = await run(evtx, reader);

      expect(outcome.warnings).toEqual([]);
      expect(outcome.rows.length).toBe(2);

      const row1 = outcome.rows[0];
      expect(row1.recordNumber).toBe(1);
      expect(row1.eventId).toBe(1126);
      expect(row1.provider).toBe('Microsoft-Windows-Windows Defender');
      expect(row1.xml).toContain('<Data Name="Product Name">Microsoft Defender Antivirus</Data>');
      expect(row1.payload).toContain('<Data Name="Product Name">Microsoft Defender Antivirus</Data>');

      const row2 = outcome.rows[1];
      expect(row2.recordNumber).toBe(2);
      expect(row2.eventId).toBe(1126);
      expect(row2.provider).toBe('Microsoft-Windows-Windows Defender');
      expect(row2.xml).toContain('<Data Name="Product Name">Microsoft Defender Antivirus Updated</Data>');
      expect(row2.payload).toContain('<Data Name="Product Name">Microsoft Defender Antivirus Updated</Data>');
    });
  });
});
