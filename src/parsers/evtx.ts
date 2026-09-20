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
import { Cursor, magic } from '../core/binary';
import { ChunkCache, decodeRecordBinXml, type DecodedRecord } from './evtx/binxml';

const HEADER_SIZE = 4096;
const CHUNK_SIZE = 65536;
const RECORDS_START = 512;

const columns: Column[] = [
  { key: 'recordId', label: 'Record ID', type: 'num' },
  { key: 'writtenTime', label: 'Written Time', type: 'date' },
  { key: 'eventId', label: 'Event ID', type: 'num' },
  { key: 'level', label: 'Level', type: 'str' },
  { key: 'provider', label: 'Provider', type: 'str' },
  { key: 'channel', label: 'Channel', type: 'str' },
  { key: 'computer', label: 'Computer', type: 'str' },
  { key: 'userId', label: 'User ID', type: 'str' },
  { key: 'processId', label: 'Process ID', type: 'num' },
  { key: 'threadId', label: 'Thread ID', type: 'num' },
  { key: 'payload', label: 'Payload', type: 'str' },
  { key: 'xml', label: 'XML', type: 'str', secondary: true },
  { key: 'chunkNumber', label: 'Chunk', type: 'num' },
  { key: 'offset', label: 'Offset', type: 'num' },
];

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

    const headerCount = new Cursor(head, 0).seek(42).u16();

    let chunkNumber = 0;
    let foundChunks = 0;
    let offset = HEADER_SIZE;

    while (offset < reader.size) {
      if (ctx.signal?.aborted) return;

      const chunkLen = Math.min(CHUNK_SIZE, reader.size - offset);
      const chunk = await reader.bytes(offset, chunkLen);

      if (!magic(chunk, 'ElfChnk\0', 0)) {
        ctx.warn(offset, 'invalid chunk signature, expected ElfChnk\\0; skipping chunk');
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

        yield {
          recordId: Number(id),
          writtenTime: written,
          eventId: decoded?.eventId ?? null,
          level: decoded?.level ?? null,
          provider: decoded?.provider ?? null,
          channel: decoded?.channel ?? null,
          computer: decoded?.computer ?? null,
          userId: decoded?.userId ?? null,
          processId: decoded?.processId ?? null,
          threadId: decoded?.threadId ?? null,
          payload: decoded?.payload ?? null,
          xml: decoded?.xml ?? null,
          chunkNumber,
          recordSize: size,
          dataLength: size - 28,
          offset: offset + pos,
        };

        pos += size;
      }

      if (truncated) break;

      offset += chunkLen;
      chunkNumber++;
    }

    if (foundChunks !== headerCount) {
      ctx.warn(0, `header claims ${headerCount} chunks but ${foundChunks} were found`);
    }
  },
};
