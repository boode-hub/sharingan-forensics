/**
 * Windows Prefetch parser (.pf files).
 *
 * Ported from Eric Zimmerman's Prefetch library (the Version17, Version23,
 * Version26 and Version30or31 classes) and PECmd's output.
 *
 * One row per referenced entry rather than one row per file. PECmd's CSV puts
 * a whole prefetch file on a single line, with every loaded file crammed into
 * one comma-joined cell and every directory into another; that works when you
 * are processing a directory of thousands of .pf files, but this tool is
 * handed one file at a time, and a single row of joined text is not something
 * an analyst can filter or sort. The run times, loaded files, directories and
 * volumes therefore each become rows, and nothing is summarised away.
 *
 * Format references:
 *   - https://github.com/EricZimmerman/Prefetch
 *   - https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc
 */
import type { Column, Parser, Reader, Ctx, Row } from '../core/types';
import { Cursor, filetime, magic, utf16, utf16Raw } from '../core/binary';
import { unwrapMam } from '../core/xpress';

const columns: Column[] = [
  { key: 'entryType', label: 'Entry Type', type: 'str' },
  { key: 'path', label: 'Path', type: 'str' },
  { key: 'runTime', label: 'Run Time', type: 'date' },
  { key: 'mftEntry', label: 'MFT Entry', type: 'num' },
  { key: 'mftSequence', label: 'MFT Sequence', type: 'num' },
  { key: 'volumeDevice', label: 'Volume Device', type: 'str' },
  { key: 'volumeSerial', label: 'Volume Serial', type: 'str' },
  { key: 'volumeCreated', label: 'Volume Created', type: 'date' },
  { key: 'executable', label: 'Executable', type: 'str' },
  { key: 'lastRun', label: 'Last Run', type: 'date' },
  { key: 'runCount', label: 'Run Count', type: 'num' },
  { key: 'hash', label: 'Hash', type: 'str' },
  { key: 'size', label: 'Size', type: 'num' },
  { key: 'version', label: 'Version', type: 'str' },
  { key: 'sourceFile', label: 'Source File', type: 'str' },
  { key: 'offset', label: 'Offset', type: 'num', secondary: true },
];

const HEADER_SIZE = 84;

/**
 * Where each field sits varies by version. These are his numbers, relative to
 * the start of the file information block at offset 84.
 */
interface Layout {
  /** Version description, exactly as his Version enum spells it. */
  description: string;
  infoSize: number;
  /** Number of 8-byte run times, and the offset of the first. */
  runTimeCount: number;
  runTimeOffset: number;
  runCountOffset: number;
  volumeEntrySize: number;
  fileMetricSize: number;
}

const LAYOUTS: Record<number, Layout> = {
  17: {
    description: 'Windows XP or Windows Server 2003',
    infoSize: 68,
    runTimeCount: 1,
    runTimeOffset: 36,
    runCountOffset: 60,
    volumeEntrySize: 40,
    fileMetricSize: 20,
  },
  23: {
    description: 'Windows Vista or Windows 7',
    infoSize: 156,
    runTimeCount: 1,
    runTimeOffset: 44,
    runCountOffset: 68,
    volumeEntrySize: 104,
    fileMetricSize: 32,
  },
  26: {
    description: 'Windows 8.0, Windows 8.1, or Windows Server 2012(R2)',
    infoSize: 224,
    runTimeCount: 8,
    runTimeOffset: 44,
    runCountOffset: 124,
    volumeEntrySize: 104,
    fileMetricSize: 32,
  },
  30: {
    description: 'Windows 10 or Windows 11',
    infoSize: 224,
    runTimeCount: 8,
    runTimeOffset: 44,
    runCountOffset: 124,
    volumeEntrySize: 96,
    fileMetricSize: 32,
  },
  31: {
    description: 'Windows 11',
    infoSize: 224,
    runTimeCount: 8,
    runTimeOffset: 44,
    runCountOffset: 124,
    volumeEntrySize: 96,
    fileMetricSize: 32,
  },
};

interface Header {
  version: number;
  description: string;
  fileSize: number;
  executable: string;
  hash: string;
}

function parseHeader(buf: Uint8Array, ctx: Ctx): Header | null {
  if (buf.length < HEADER_SIZE) {
    ctx.warn(0, 'truncated header');
    return null;
  }

  const c = new Cursor(buf, 0);
  const version = c.u32();
  const sig = String.fromCharCode(...c.take(4));
  if (sig !== 'SCCA') {
    ctx.warn(4, `expected SCCA signature, got ${JSON.stringify(sig)}`);
    return null;
  }

  c.u32(); // unknown
  const fileSize = c.u32();

  // The name field is a fixed 60 bytes, NUL-padded.
  const executable = c.utf16(60).replace(/\0[\s\S]*$/, '').trim();
  const hash = c.u32();

  const known = LAYOUTS[version];
  if (!known) {
    ctx.warn(0, `unrecognised prefetch version ${version}; reading it as version 30`);
  }

  return {
    version,
    description: known?.description ?? `Unknown (${version})`,
    fileSize,
    executable,
    // His Header formats the hash as upper-case hex with no padding.
    hash: (hash >>> 0).toString(16).toUpperCase(),
  };
}

/** A file reference, as packed into 8 bytes of a volume's file-reference list. */
function mftReference(b: Uint8Array): { entry: number | null; sequence: number | null } {
  if (b.length < 8) return { entry: null, sequence: null };
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const low = dv.getUint32(0, true);
  const high = dv.getUint16(4, true);
  const sequence = dv.getUint16(6, true);
  return {
    entry: high === 0 ? low : low + high * 16_777_216,
    // He reports a zero sequence number as absent rather than as zero.
    sequence: sequence === 0 ? null : sequence,
  };
}

/** NUL-separated UTF-16 strings, as the filename-strings block stores them. */
function splitStrings(buf: Uint8Array, offset: number, size: number): string[] {
  if (size <= 0 || offset < 0 || offset + size > buf.length) return [];
  return utf16Raw(buf.subarray(offset, offset + size))
    .split('\0')
    .filter((s) => s.length > 0);
}

export const prefetch: Parser = {
  id: 'prefetch',
  name: 'Prefetch',
  ezTool: 'PECmd',
  extensions: ['.pf'],
  columns,
  sniff(head: Uint8Array, _filename: string): boolean {
    if (magic(head, 'MAM', 0)) return true;
    if (magic(head, 'SCCA', 4)) return true;
    return false;
  },
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    const rawBuf = await reader.bytes(0, reader.size);

    let buf: Uint8Array;
    try {
      buf = unwrapMam(rawBuf);
    } catch (e) {
      ctx.warn(0, `MAM decompression failed: ${(e as Error).message}`);
      return;
    }

    const header = parseHeader(buf, ctx);
    if (!header) return;

    const layout = LAYOUTS[header.version] ?? LAYOUTS[30];

    if (buf.length < HEADER_SIZE + layout.infoSize) {
      ctx.warn(HEADER_SIZE, 'truncated file information block');
      return;
    }

    const info = new Cursor(buf, HEADER_SIZE);
    const fileMetricsOffset = info.u32();
    const fileMetricsCount = info.u32();
    info.u32(); // trace chains offset
    info.u32(); // trace chains count
    const filenamesOffset = info.u32();
    const filenamesSize = info.u32();
    const volumesOffset = info.u32();
    const volumeCount = info.u32();
    info.u32(); // volumes information size

    const runTimes: Date[] = [];
    info.seek(HEADER_SIZE + layout.runTimeOffset);
    for (let i = 0; i < layout.runTimeCount; i++) {
      const t = filetime(info.u64());
      if (t) runTimes.push(t);
    }

    let runCount = new Cursor(buf, HEADER_SIZE + layout.runCountOffset).u32();
    if (header.version === 30 || header.version === 31) {
      // Newer Windows 10 builds shift the counter back eight bytes. He detects
      // that by checking whether the slot just before it is populated.
      const probe = new Cursor(buf, HEADER_SIZE + layout.runCountOffset - 4).u32();
      if (probe !== 0) {
        runCount = new Cursor(buf, HEADER_SIZE + layout.runCountOffset - 8).u32();
      }
    }

    const filenames = splitStrings(buf, filenamesOffset, filenamesSize);
    if (filenames.length === 0 && filenamesSize > 0) {
      ctx.warn(filenamesOffset, 'filename strings block did not yield any names');
    }

    // Each file metric describes the filename at the same index, and carries
    // that file's MFT reference. Without it a loaded file is just a path; with
    // it the entry can be tied to a specific record in $MFT.
    const references: Array<{ entry: number | null; sequence: number | null }> = [];
    if (layout.fileMetricSize === 32) {
      for (let i = 0; i < fileMetricsCount; i++) {
        const at = fileMetricsOffset + i * 32;
        if (at + 32 > buf.length) {
          ctx.warn(at, 'file metrics run past the end of the file');
          break;
        }
        references.push(mftReference(buf.subarray(at + 24, at + 32)));
      }
    }

    const context = {
      executable: header.executable,
      lastRun: runTimes[0] ?? null,
      runCount,
      hash: header.hash,
      size: header.fileSize,
      version: header.description,
      sourceFile: reader.name,
    };

    for (let i = 0; i < runTimes.length; i++) {
      yield {
        ...context,
        entryType: 'Run',
        path: header.executable,
        runTime: runTimes[i],
        mftEntry: null,
        mftSequence: null,
        volumeDevice: null,
        volumeSerial: null,
        volumeCreated: null,
        offset: HEADER_SIZE + layout.runTimeOffset + i * 8,
      };
    }

    let emittedFiles = false;

    for (let v = 0; v < volumeCount; v++) {
      if (ctx.signal?.aborted) return;

      const at = volumesOffset + v * layout.volumeEntrySize;
      if (at + layout.volumeEntrySize > buf.length) {
        ctx.warn(at, `volume ${v} runs past the end of the file`);
        break;
      }

      const vc = new Cursor(buf, at);
      const devicePathOffset = vc.u32();
      const devicePathChars = vc.u32();
      const created = vc.filetime();
      const serial = vc.u32();
      const fileRefOffset = vc.u32();
      const fileRefSize = vc.u32();
      const dirStringsOffset = vc.u32();
      const dirStringCount = vc.u32();

      const nameAt = volumesOffset + devicePathOffset;
      let device: string | null = null;
      if (nameAt >= 0 && nameAt + devicePathChars * 2 <= buf.length) {
        device = utf16(buf.subarray(nameAt, nameAt + devicePathChars * 2));
      } else {
        ctx.warn(nameAt, `volume ${v} device name runs past the end of the file`);
      }

      const volume = {
        volumeDevice: device,
        // Upper-case hex with no padding, as his VolumeInfo formats it.
        volumeSerial: (serial >>> 0).toString(16).toUpperCase(),
        volumeCreated: created,
      };

      yield {
        ...context,
        ...volume,
        entryType: 'Volume',
        path: device,
        runTime: null,
        mftEntry: null,
        mftSequence: null,
        offset: at,
      };

      // File references: a version marker and a count, then 8 bytes each.
      const refsAt = volumesOffset + fileRefOffset;
      const refs: Array<{ entry: number | null; sequence: number | null }> = [];
      if (fileRefSize > 8 && refsAt + fileRefSize <= buf.length) {
        const declared = new Cursor(buf, refsAt + 4).u32();
        for (let i = 0; i < declared && 8 + i * 8 + 8 <= fileRefSize; i++) {
          const p = refsAt + 8 + i * 8;
          refs.push(mftReference(buf.subarray(p, p + 8)));
        }
      } else if (fileRefSize > 0) {
        ctx.warn(refsAt, `volume ${v} file references run past the end of the file`);
      }

      // The volume's own list of referenced MFT records. It is a different
      // list from the loaded filenames and is usually longer, so it cannot be
      // folded into those rows; without it an analyst loses every reference
      // that has no name in this file.
      for (let i = 0; i < refs.length; i++) {
        if (ctx.signal?.aborted) return;
        yield {
          ...context,
          ...volume,
          entryType: 'File Reference',
          path: null,
          runTime: null,
          mftEntry: refs[i].entry,
          mftSequence: refs[i].sequence,
          offset: refsAt + 8 + i * 8,
        };
      }

      // Directory strings: a character count, then that many UTF-16 characters
      // plus a terminator.
      let p = volumesOffset + dirStringsOffset;
      for (let k = 0; k < dirStringCount; k++) {
        if (ctx.signal?.aborted) return;
        if (p + 2 > buf.length) {
          ctx.warn(p, `volume ${v} directory strings run past the end of the file`);
          break;
        }
        const chars = new Cursor(buf, p).u16();
        const start = p + 2;
        const end = start + chars * 2;
        if (end > buf.length) {
          ctx.warn(p, `volume ${v} directory string ${k} runs past the end of the file`);
          break;
        }
        yield {
          ...context,
          ...volume,
          entryType: 'Directory',
          path: utf16(buf.subarray(start, end)).replace(/\0+$/, ''),
          runTime: null,
          mftEntry: null,
          mftSequence: null,
          offset: p,
        };
        p = end + 2; // skip the NUL terminator
      }

      // The filename list is not split per volume, so it is emitted once,
      // alongside the first volume.
      if (!emittedFiles) {
        emittedFiles = true;
        for (let i = 0; i < filenames.length; i++) {
          if (ctx.signal?.aborted) return;
          const ref = references[i] ?? { entry: null, sequence: null };
          yield {
            ...context,
            entryType: 'File',
            path: filenames[i],
            runTime: null,
            mftEntry: ref.entry,
            mftSequence: ref.sequence,
            volumeDevice: null,
            volumeSerial: null,
            volumeCreated: null,
            offset: filenamesOffset,
          };
        }
      }
    }

    if (!emittedFiles) {
      if (volumeCount === 0) {
        ctx.warn(HEADER_SIZE, 'volume count is zero; listing loaded files without volume context');
      }
      for (let i = 0; i < filenames.length; i++) {
        yield {
          ...context,
          entryType: 'File',
          path: filenames[i],
          runTime: null,
          mftEntry: references[i]?.entry ?? null,
          mftSequence: references[i]?.sequence ?? null,
          volumeDevice: null,
          volumeSerial: null,
          volumeCreated: null,
          offset: filenamesOffset,
        };
      }
    }
  },
};
