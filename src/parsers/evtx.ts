/**
 * Windows XML Event Log (EVTX) parser with full BinXML decoding.
 *
 * Format references:
 *   - [MS-EVEN6]: Event Log Remoting Protocol
 *   - libevtx documentation:
 *       https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
 *   - Eric Zimmerman's evtx project (EvtxECmd):
 *       https://github.com/EricZimmerman/evtx
 */
import type { Column, Parser, Reader, Ctx, Row } from '../core/types';
import { Cursor, filetime, magic } from '../core/binary';
import { ChunkCache, decodeRecordBinXml, loadEventMaps, type DecodedRecord } from './evtx/binxml';

const HEADER_SIZE = 4096;
const CHUNK_SIZE = 65536;
const RECORDS_START = 512;

// Column set and order mirror EvtxECmd's own CSV output (see the class map in
// his Program.cs), so an analyst moving between the two tools reads the same
// fields in the same places. The last three are ours: they locate a record in
// the file, which his JSON output also carries.
const columns: Column[] = [
  { key: 'recordNumber', label: 'Record Number', type: 'num' },
  { key: 'eventRecordId', label: 'Event Record Id', type: 'str' },
  { key: 'timeCreated', label: 'Time Created', type: 'date' },
  { key: 'eventId', label: 'Event Id', type: 'num' },
  { key: 'level', label: 'Level', type: 'str' },
  { key: 'provider', label: 'Provider', type: 'str' },
  { key: 'channel', label: 'Channel', type: 'str' },
  { key: 'processId', label: 'Process Id', type: 'num' },
  { key: 'threadId', label: 'Thread Id', type: 'num' },
  { key: 'computer', label: 'Computer', type: 'str' },
  { key: 'userId', label: 'User Id', type: 'str' },
  { key: 'mapDescription', label: 'Map Description', type: 'str' },
  { key: 'userName', label: 'User Name', type: 'str' },
  { key: 'remoteHost', label: 'Remote Host', type: 'str' },
  { key: 'payloadData1', label: 'Payload Data1', type: 'str' },
  { key: 'payloadData2', label: 'Payload Data2', type: 'str' },
  { key: 'payloadData3', label: 'Payload Data3', type: 'str' },
  { key: 'payloadData4', label: 'Payload Data4', type: 'str' },
  { key: 'payloadData5', label: 'Payload Data5', type: 'str' },
  { key: 'payloadData6', label: 'Payload Data6', type: 'str' },
  { key: 'executableInfo', label: 'Executable Info', type: 'str' },
  { key: 'hiddenRecord', label: 'Hidden Record', type: 'bool' },
  { key: 'sourceFile', label: 'Source File', type: 'str' },
  { key: 'keywords', label: 'Keywords', type: 'str' },
  { key: 'payload', label: 'Payload', type: 'str' },
  { key: 'writtenTime', label: 'Written Time (header)', type: 'date', secondary: true },
  { key: 'xml', label: 'XML', type: 'str', secondary: true },
  { key: 'chunkNumber', label: 'Chunk', type: 'num' },
  { key: 'extraDataOffset', label: 'Extra Data Offset', type: 'num', secondary: true },
  { key: 'offset', label: 'Offset', type: 'num' },
];

/**
 * Looks for a second event record hidden in the slack after a record's BinXML.
 *
 * Writing one record inside another is how the DanderSpritz eventlogedit
 * module hides an event: the outer record's size covers both, so a reader that
 * stops at the end of the first BinXML stream never sees the second. EvtxECmd
 * looks for the 0x2a2a signature within fifteen bytes of where the stream
 * ended, which is what this does.
 *
 * Returns the offset of the hidden record within the chunk, or null.
 */
function findHiddenRecord(
  chunk: Uint8Array,
  recordStart: number,
  binXmlEndInChunk: number,
  recordEnd: number,
  outerId: bigint,
): number | null {
  const limit = Math.min(binXmlEndInChunk + 15, recordEnd - 1);
  for (let at = binXmlEndInChunk; at < limit; at++) {
    if (chunk[at] !== 0x2a || chunk[at + 1] !== 0x2a) continue;
    // The record signature 0x00002a2a is written 2a 2a 00 00, so the record
    // begins at the first 0x2a rather than before it.
    const start = at;
    if (start < recordStart || start + 24 > recordEnd) return null;

    const view = new DataView(chunk.buffer, chunk.byteOffset + start, 24);
    const size = view.getUint32(4, true);
    const id = view.getBigUint64(8, true);
    if (id === outerId) return null; // the same record, not a hidden one
    if (size < 28 || start + size > recordEnd) return null;
    return start;
  }
  return null;
}

export const evtx: Parser = {
  id: 'evtx',
  name: 'Windows Event Log (EVTX)',
  ezTool: 'EvtxECmd',
  extensions: ['.evtx'],
  columns,
  sniff(head: Uint8Array, _filename: string): boolean {
    return magic(head, 'ElfFile\0', 0);
  },
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    const head = await reader.bytes(0, HEADER_SIZE);
    if (!magic(head, 'ElfFile\0', 0)) {
      ctx.warn(0, 'invalid EVTX signature, expected ElfFile\\0');
      return;
    }

    // Pull in the event maps before any record is decoded; they are loaded on
    // demand so that opening a prefetch file does not download them.
    await loadEventMaps();

    const headerCount = new Cursor(head, 0).seek(42).u16();

    let chunkNumber = 0;
    let foundChunks = 0;
    let records = 0;
    let offset = HEADER_SIZE;

    while (offset < reader.size) {
      if (ctx.signal?.aborted) return;

      const chunkLen = Math.min(CHUNK_SIZE, reader.size - offset);
      const chunk = await reader.bytes(offset, chunkLen);

      if (!magic(chunk, 'ElfChnk\0', 0)) {
        // An EVTX file is preallocated, so space past the last written chunk
        // is normally just zeroes. Only say something when it is not: that is
        // either a partially overwritten chunk or a carving target, and worth
        // an analyst's attention.
        if (chunk.subarray(0, 512).some((b) => b !== 0)) {
          ctx.warn(offset, 'invalid chunk signature, expected ElfChnk\\0; skipping chunk');
        }
        offset += chunkLen;
        chunkNumber++;
        continue;
      }

      foundChunks++;

      // Chunk header cursor starts at offset 8 to skip 'ElfChnk\0' signature
      const c = new Cursor(chunk, 8);
      c.u64(); // first event record number (chunk offset 8..15)
      c.u64(); // last event record number (chunk offset 16..23)
      c.u64(); // first event record identifier (chunk offset 24..31)
      c.u64(); // last event record identifier (chunk offset 32..39)
      c.u32(); // header size (128) (chunk offset 40..43)
      c.u32(); // last record offset (chunk offset 44..47)
      const freeOffset = c.u32(); // free space offset (chunk offset 48..51)

      let end = freeOffset;
      if (freeOffset > chunk.length || freeOffset < RECORDS_START) {
        ctx.warn(offset + 48, `free space offset ${freeOffset} is out of bounds; using chunk end`);
        end = chunk.length;
      }

      // Initialize per-chunk caches for templates and strings
      const chunkCache = new ChunkCache(chunk, chunkNumber);

      let pos = RECORDS_START;
      let truncated = false;

      while (pos < end) {
        if (ctx.signal?.aborted) return;

        const rec = new Cursor(chunk, pos);
        const sig = rec.u32();
        const size = rec.u32();
        const id = rec.u64();
        const written = rec.filetime();

        if (sig !== 0x00002a2a || size < 28 || pos + size > end) {
          ctx.warn(offset + pos, `corrupt record (sig=0x${sig.toString(16)}, size=${size}); stopping this chunk`);
          break;
        }

        // Truncated final chunk: a record that runs past the chunk's available
        // bytes but is otherwise intact still yields its header fields.
        if (pos + size > chunk.length) {
          truncated = true;
          ctx.warn(offset + pos, 'record extends past chunk end; emitting header fields only');
        }

        const trail = new Cursor(chunk, pos + size - 4).u32();
        if (trail !== size) {
          ctx.warn(offset + pos, `trailing size copy ${trail} does not match leading size ${size}`);
        }

        const payloadBytes = chunk.subarray(pos + 24, pos + size - 4);
        let decoded: DecodedRecord | null = null;

        if (!truncated && payloadBytes.length > 0) {
          try {
            decoded = decodeRecordBinXml(payloadBytes, pos + 24, chunk, chunkCache);
          } catch (err) {
            ctx.warn(offset + pos, `BinXML decode failed: ${(err as Error).message}`);
          }
        }

        // A record whose BinXML ends early may be concealing another one.
        let hiddenAt: number | null = null;
        if (decoded && !truncated) {
          hiddenAt = findHiddenRecord(
            chunk,
            pos,
            pos + 24 + decoded.binXmlEnd,
            pos + size,
            id,
          );
        }

        records++;
        yield {
          // EvtxECmd's RecordNumber is this identifier from the record header,
          // not a running count of records read.
          recordNumber: Number(id),
          eventRecordId: decoded?.eventRecordId ?? null,
          timeCreated: decoded?.timeCreated ?? written,
          writtenTime: written,
          eventId: decoded?.eventId ?? null,
          level: decoded?.level ?? null,
          provider: decoded?.provider ?? null,
          channel: decoded?.channel ?? null,
          computer: decoded?.computer ?? null,
          mapDescription: decoded?.mapDescription ?? null,
          userName: decoded?.userName ?? null,
          remoteHost: decoded?.remoteHost ?? null,
          executableInfo: decoded?.executableInfo ?? null,
          hiddenRecord: false,
          payloadData1: decoded?.payloadData1 ?? null,
          payloadData2: decoded?.payloadData2 ?? null,
          payloadData3: decoded?.payloadData3 ?? null,
          payloadData4: decoded?.payloadData4 ?? null,
          payloadData5: decoded?.payloadData5 ?? null,
          payloadData6: decoded?.payloadData6 ?? null,
          userId: decoded?.userId ?? null,
          processId: decoded?.processId ?? null,
          threadId: decoded?.threadId ?? null,
          keywords: decoded?.keywords ?? null,
          sourceFile: reader.name,
          payload: decoded?.payload ?? null,
          xml: decoded?.xml ?? null,
          chunkNumber,
          recordSize: size,
          dataLength: size - 28,
          extraDataOffset: hiddenAt === null ? null : offset + hiddenAt,
          offset: offset + pos,
        };

        if (hiddenAt !== null) {
          const hv = new DataView(chunk.buffer, chunk.byteOffset + hiddenAt, 24);
          const hiddenSize = hv.getUint32(4, true);
          const hiddenId = hv.getBigUint64(8, true);
          const hiddenWritten = filetime(hv.getBigUint64(16, true));

          ctx.warn(
            offset + hiddenAt,
            `a second event record is hidden inside record ${id} — this is what DanderSpritz eventlogedit does to conceal an event`,
          );

          let hidden: DecodedRecord | null = null;
          try {
            hidden = decodeRecordBinXml(
              chunk.subarray(hiddenAt + 24, Math.min(hiddenAt + hiddenSize - 4, chunk.length)),
              hiddenAt + 24,
              chunk,
              chunkCache,
            );
          } catch (err) {
            ctx.warn(offset + hiddenAt, `hidden record did not decode: ${(err as Error).message}`);
          }

          records++;
          yield {
            recordNumber: Number(hiddenId),
            eventRecordId: hidden?.eventRecordId ?? null,
            timeCreated: hidden?.timeCreated ?? hiddenWritten,
            writtenTime: hiddenWritten,
            eventId: hidden?.eventId ?? null,
            level: hidden?.level ?? null,
            provider: hidden?.provider ?? null,
            channel: hidden?.channel ?? null,
            computer: hidden?.computer ?? null,
            mapDescription: hidden?.mapDescription ?? null,
            userName: hidden?.userName ?? null,
            remoteHost: hidden?.remoteHost ?? null,
            executableInfo: hidden?.executableInfo ?? null,
            hiddenRecord: true,
            payloadData1: hidden?.payloadData1 ?? null,
            payloadData2: hidden?.payloadData2 ?? null,
            payloadData3: hidden?.payloadData3 ?? null,
            payloadData4: hidden?.payloadData4 ?? null,
            payloadData5: hidden?.payloadData5 ?? null,
            payloadData6: hidden?.payloadData6 ?? null,
            userId: hidden?.userId ?? null,
            processId: hidden?.processId ?? null,
            threadId: hidden?.threadId ?? null,
            keywords: hidden?.keywords ?? null,
            sourceFile: reader.name,
            payload: hidden?.payload ?? null,
            xml: hidden?.xml ?? null,
            chunkNumber,
            recordSize: hiddenSize,
            dataLength: hiddenSize - 28,
            extraDataOffset: null,
            offset: offset + hiddenAt,
          };
        }

        pos += size;
      }

      if (truncated) break;

      offset += chunkLen;
      chunkNumber++;
    }

    if (foundChunks !== headerCount) {
      ctx.warn(0, `header claims ${headerCount} chunks but ${foundChunks} were found`);
    }

    // An empty log is a normal thing to find, but an empty grid with nothing
    // said looks like a parser that gave up. Say which it is.
    if (records === 0) {
      ctx.warn(0, 'this log holds no records; the channel is enabled but nothing has been written to it');
    }
  },
};
