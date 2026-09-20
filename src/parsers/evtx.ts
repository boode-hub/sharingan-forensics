/**
 * Windows XML Event Log (EVTX) parser — record framing only.
 * Format reference:
 *   - https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
 *
 * Scope: the file header, the 65536-byte chunks, and the event-record framing.
 * The BinXML payload inside each record is not decoded here — it is a separate
 * job. Each record yields its payload length and moves on.
 */
import type { Column, Parser, Reader, Ctx, Row } from '../core/types';
import { Cursor, magic } from '../core/binary';

const HEADER_SIZE = 4096;
const CHUNK_SIZE = 65536;
const RECORDS_START = 512;

const columns: Column[] = [
  { key: 'recordId', label: 'Record ID', type: 'num' },
  { key: 'writtenTime', label: 'Written Time', type: 'date' },
  { key: 'chunkNumber', label: 'Chunk', type: 'num' },
  { key: 'recordSize', label: 'Record Size', type: 'num' },
  { key: 'dataLength', label: 'Data Length', type: 'num' },
  { key: 'offset', label: 'Offset', type: 'num', secondary: true },
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

      const c = new Cursor(chunk, 0);
      c.u64(); // first event record number
      c.u64(); // last event record number
      c.u64(); // first event record identifier
      c.u64(); // last event record identifier
      c.u32(); // header size (128)
      c.u32(); // last record offset
      const freeOffset = c.u32();

      let end = freeOffset;
      if (freeOffset > chunk.length || freeOffset < RECORDS_START) {
        ctx.warn(offset + 48, `free space offset ${freeOffset} is out of bounds; using chunk end`);
        end = chunk.length;
      }

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

        yield {
          recordId: Number(id),
          writtenTime: written,
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
