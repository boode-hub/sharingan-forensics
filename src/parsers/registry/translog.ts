/**
 * Registry transaction log replay.
 *
 * Ported from Eric Zimmerman's TransactionLog, TransactionLogEntry and Marvin
 * classes in https://github.com/EricZimmerman/Registry, which is what his `rla`
 * tool uses.
 *
 * Windows writes registry changes to SYSTEM.LOG1 and SYSTEM.LOG2 before it
 * writes them to the hive, and a hive captured from a running machine is
 * almost always behind its logs. Reading such a hive without replaying them
 * gives an answer that was true at some earlier point, with no indication that
 * it is stale: a key the logs show as deleted is still present, and a value
 * the logs show as changed still has its old data. Every large hive in a live
 * collection is in this state.
 */
import type { Ctx, Reader } from '../../core/types';
import { magic } from '../../core/binary';
import { bufReader } from '../../core/reader';

/** A page of hive bytes that a log entry supersedes. */
interface DirtyPage {
  /** Offset into the hive's hbin area, so 4096 bytes past the file start. */
  offset: number;
  size: number;
  bytes: Uint8Array;
}

interface LogEntry {
  sequenceNumber: number;
  pages: DirtyPage[];
  /** Whether both Marvin hashes match, which is what makes an entry usable. */
  valid: boolean;
}

export interface ReplayResult {
  bytes: Uint8Array;
  entriesApplied: number;
  pagesApplied: number;
  entriesRejected: number;
  newSequenceNumber: number;
  /** Which log supplied the applied entries, in the order they were applied. */
  logsUsed: string[];
}

const MARVIN_SEED = 0x82ef4d887a4e55c5n;

function rotl(value: number, shift: number): number {
  return ((value << shift) | (value >>> (32 - shift))) >>> 0;
}

/**
 * The Marvin hash Windows uses to protect a log entry.
 *
 * An entry whose hashes do not match was not written completely, and applying
 * it would corrupt the hive rather than update it, so it is skipped.
 */
export function marvin(data: Uint8Array, seed: bigint = MARVIN_SEED): bigint {
  let p0 = Number(seed & 0xffffffffn) >>> 0;
  let p1 = Number((seed >> 32n) & 0xffffffffn) >>> 0;

  const block = () => {
    p1 ^= p0;
    p0 = rotl(p0, 20);
    p0 = (p0 + p1) >>> 0;
    p1 = rotl(p1, 9);
    p1 ^= p0;
    p0 = rotl(p0, 27);
    p0 = (p0 + p1) >>> 0;
    p1 = rotl(p1, 19);
  };

  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let at = 0;
  let left = data.length;

  while (left >= 8) {
    p0 = (p0 + dv.getUint32(at, true)) >>> 0;
    block();
    p0 = (p0 + dv.getUint32(at + 4, true)) >>> 0;
    block();
    at += 8;
    left -= 8;
  }

  // The tail is padded with a single high bit past the last byte, so that
  // trailing zero bytes still change the hash.
  switch (left) {
    case 7:
      p0 = (p0 + dv.getUint32(at, true)) >>> 0;
      at += 4;
      block();
      p0 = (p0 + (0x80000000 | (data[at + 2] << 16) | dv.getUint16(at, true))) >>> 0;
      break;
    case 6:
      p0 = (p0 + dv.getUint32(at, true)) >>> 0;
      at += 4;
      block();
      p0 = (p0 + (0x800000 | dv.getUint16(at, true))) >>> 0;
      break;
    case 5:
      p0 = (p0 + dv.getUint32(at, true)) >>> 0;
      at += 4;
      block();
      p0 = (p0 + (0x8000 | data[at])) >>> 0;
      break;
    case 4:
      p0 = (p0 + dv.getUint32(at, true)) >>> 0;
      block();
      p0 = (p0 + 0x80) >>> 0;
      break;
    case 3:
      p0 = (p0 + (0x80000000 | (data[at + 2] << 16) | dv.getUint16(at, true))) >>> 0;
      break;
    case 2:
      p0 = (p0 + (0x800000 | dv.getUint16(at, true))) >>> 0;
      break;
    case 1:
      p0 = (p0 + (0x8000 | data[at])) >>> 0;
      break;
    default:
      p0 = (p0 + 0x80) >>> 0;
      break;
  }

  block();
  block();

  return ((BigInt(p1) << 32n) | BigInt(p0)) & 0xffffffffffffffffn;
}

/** Reads the HvLE entries of one transaction log. Entries start at 0x200. */
export function parseLog(bytes: Uint8Array): LogEntry[] {
  const entries: LogEntry[] = [];
  if (bytes.length < 0x200 + 40) return entries;

  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let index = 0x200;

  while (index + 40 <= bytes.length) {
    // Logs are reused rather than truncated, so the first thing that is not an
    // entry is the end of the current generation, not an error.
    if (
      bytes[index] !== 0x48 ||
      bytes[index + 1] !== 0x76 ||
      bytes[index + 2] !== 0x4c ||
      bytes[index + 3] !== 0x45
    ) {
      break;
    }

    const size = dv.getUint32(index + 4, true);
    if (size < 40 || index + size > bytes.length) break;

    const sequenceNumber = dv.getInt32(index + 12, true);
    const dirtyPageCount = dv.getInt32(index + 20, true);
    const hash1 = dv.getBigUint64(index + 24, true);
    const hash2 = dv.getBigUint64(index + 32, true);

    if (dirtyPageCount < 0 || 40 + dirtyPageCount * 8 > size) break;

    const pages: DirtyPage[] = [];
    let at = index + 40;
    for (let i = 0; i < dirtyPageCount; i++) {
      pages.push({
        offset: dv.getInt32(at, true),
        size: dv.getInt32(at + 4, true),
        bytes: new Uint8Array(0),
      });
      at += 8;
    }

    // The page data follows as a run of hbins, in the order the pages listed.
    let ok = at + 4 <= bytes.length;
    for (const page of pages) {
      if (!ok || page.size < 0 || at + page.size > index + size) {
        ok = false;
        break;
      }
      page.bytes = bytes.subarray(at, at + page.size);
      at += page.size;
    }

    const entry = bytes.subarray(index, index + size);
    const valid =
      ok &&
      marvin(entry.subarray(40)) === hash1 &&
      marvin(entry.subarray(0, 32)) === hash2;

    entries.push({ sequenceNumber, pages, valid });
    index += size;
  }

  return entries;
}

/**
 * Applies the logs to a copy of the hive.
 *
 * Entries are applied in sequence order across both logs, as Windows would
 * have replayed them, and an entry whose hashes do not verify is skipped
 * rather than trusted.
 */
export function replay(
  hive: Uint8Array,
  logs: Array<{ name: string; bytes: Uint8Array }>,
  hiveSequence: number,
): ReplayResult {
  const out = new Uint8Array(hive);
  const collected: Array<{ name: string; entry: LogEntry }> = [];
  let rejected = 0;

  for (const log of logs) {
    for (const entry of parseLog(log.bytes)) {
      if (!entry.valid) {
        rejected++;
        continue;
      }
      // An entry older than the hive itself has already been written out.
      if (entry.sequenceNumber < hiveSequence) continue;
      collected.push({ name: log.name, entry });
    }
  }

  collected.sort((a, b) => a.entry.sequenceNumber - b.entry.sequenceNumber);

  let pagesApplied = 0;
  let newSequenceNumber = hiveSequence;
  const logsUsed: string[] = [];

  for (const { name, entry } of collected) {
    for (const page of entry.pages) {
      const at = page.offset + 0x1000;
      if (at < 0 || at + page.bytes.length > out.length) continue;
      out.set(page.bytes, at);
      pagesApplied++;
    }
    newSequenceNumber = entry.sequenceNumber;
    if (!logsUsed.includes(name)) logsUsed.push(name);
  }

  // A replayed hive is clean by definition, so make its header say so;
  // otherwise it would still read as dirty and warn about itself.
  if (collected.length > 0 && out.length >= 12) {
    const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
    dv.setUint32(4, newSequenceNumber, true);
    dv.setUint32(8, newSequenceNumber, true);
  }

  return {
    bytes: out,
    entriesApplied: collected.length,
    pagesApplied,
    entriesRejected: rejected,
    newSequenceNumber,
    logsUsed,
  };
}

/**
 * The hive brought up to date from the logs opened with it, or the hive as it
 * is when it is clean or no logs came with it. Every reader of a hive goes
 * through this, so an artifact read out of a hive is as current as the hive
 * view of the same file.
 */
export async function replayIfDirty(source: Reader, ctx: Ctx): Promise<Reader> {
  let reader = source;

  // A hive whose two sequence numbers disagree has changes sitting in its
  // transaction logs. If the logs were opened with it, replay them first, so
  // what follows is the hive as the machine would have seen it rather than
  // as it was last flushed.
  if (ctx.siblings && ctx.siblings.length > 0 && reader.size >= 4096) {
    const head = await reader.bytes(0, 12);
    if (head.length >= 12 && magic(head, 'regf', 0)) {
      const hv = new DataView(head.buffer, head.byteOffset, head.byteLength);
      const primary = hv.getUint32(4, true);
      const secondary = hv.getUint32(8, true);
      if (primary !== secondary) {
        const logs: Array<{ name: string; bytes: Uint8Array }> = [];
        for (const sib of ctx.siblings) {
          const bytes = await sib.bytes(0, sib.size);
          if (bytes.length > 0x200 && magic(bytes, 'regf', 0)) {
            logs.push({ name: sib.name, bytes });
          } else {
            ctx.warn(0, `${sib.name} is not a registry transaction log; ignoring it`);
          }
        }

        if (logs.length > 0) {
          const hive = await reader.bytes(0, reader.size);
          const result = replay(hive, logs, secondary);
          if (result.entriesApplied > 0) {
            reader = bufReader(result.bytes, reader.name);
            ctx.warn(
              0,
              `replayed ${result.entriesApplied} log entr${result.entriesApplied === 1 ? 'y' : 'ies'} (${result.pagesApplied} pages) from ${result.logsUsed.join(', ')}; the rows below are the hive brought up to date, not as it was captured`,
            );
          } else {
            ctx.warn(
              0,
              `the logs held nothing newer than the hive itself, so nothing was replayed${result.entriesRejected > 0 ? `; ${result.entriesRejected} entr${result.entriesRejected === 1 ? 'y' : 'ies'} failed hash verification and were skipped` : ''}`,
            );
          }
          if (result.entriesRejected > 0 && result.entriesApplied > 0) {
            ctx.warn(
              0,
              `${result.entriesRejected} log entr${result.entriesRejected === 1 ? 'y was' : 'ies were'} incomplete and skipped rather than applied`,
            );
          }
        }
      }
    }
  }
  // A hive is read by jumping from cell to cell, a value at a time; from a
  // file that is one read per cell, which made a 45 MB hive take minutes
  // against two seconds in memory. His Registry library holds the whole hive
  // too, and hives are bounded (hundreds of MB, not the gigabytes of an
  // event log), so it is read once here.
  // ponytail: whole hive in memory; a cached page reader if multi-GB hives turn up.
  return reader === source ? bufReader(await source.bytes(0, source.size), source.name) : reader;
}
