/** 100ns ticks between 1601-01-01 and 1970-01-01, already divided by 10000 (i.e. ms). */
const FILETIME_EPOCH_MS = 11644473600000;

/**
 * Windows FILETIME (100ns ticks since 1601-01-01 UTC) -> Date.
 * Returns null only for the two values that mean "unset" rather than a real
 * 1601 date; every other u64 lands inside Date's range (max u64 is year 60056),
 * so an implausible date is surfaced as-is rather than hidden.
 */
export function filetime(ticks: bigint): Date | null {
  if (ticks === 0n || ticks === 0xffffffffffffffffn) return null;
  return preciseDate(Number(ticks / 10000n) - FILETIME_EPOCH_MS, Number(ticks % 10000n));
}

/**
 * A Date that also keeps the 100ns ticks below its millisecond (0-9999). A
 * JavaScript Date holds whole milliseconds; FILETIME and EZ's tools have seven
 * fractional digits, and a timestomped $MFT entry shows in the last four.
 */
export type PreciseDate = Date & { sub?: number };

/** The 100ns ticks below a Date's millisecond; 0 for a time kept no finer. */
export const subTicks = (d: Date): number => (d as PreciseDate).sub ?? 0;

export function preciseDate(ms: number, sub: number): Date {
  const d: PreciseDate = new Date(ms);
  if (sub) d.sub = sub;
  return d;
}

/**
 * The one text form every time here is written in: ISO 8601, UTC, seven
 * fractional digits, e.g. 2024-05-01T10:00:05.1234567Z.
 */
export function iso(d: Date): string {
  if (Number.isNaN(d.getTime())) return '';
  return `${d.toISOString().slice(0, -1)}${String(subTicks(d)).padStart(4, '0')}Z`;
}

/** Reads that form back (1-7 fractional digits, Z optional), keeping every digit. */
export function parseIso(s: string): Date | null {
  const m = /^([+-]\d{6}|\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?Z?$/.exec(s.trim());
  if (!m) return null;
  const f = (m[7] ?? '').padEnd(7, '0');
  const ms = Date.parse(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}.${f.slice(0, 3)}Z`);
  return Number.isNaN(ms) ? null : preciseDate(ms, Number(f.slice(3)));
}

/** Unix seconds -> Date. 0 is treated as unset. */
export function unixtime(seconds: number): Date | null {
  if (!seconds) return null;
  const d = new Date(seconds * 1000);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** MS-DOS packed date+time (FAT) -> Date, interpreted as local-naive UTC. */
export function dosDateTime(date: number, time: number): Date | null {
  if (!date) return null;
  const y = 1980 + ((date >> 9) & 0x7f);
  const mo = (date >> 5) & 0x0f;
  const d = date & 0x1f;
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return null;
  return new Date(
    Date.UTC(y, mo - 1, d, (time >> 11) & 0x1f, (time >> 5) & 0x3f, (time & 0x1f) * 2),
  );
}

/** Microsoft mixed-endian GUID -> canonical {xxxxxxxx-xxxx-...} form, braces omitted. */
export function guid(b: Uint8Array): string {
  if (b.length < 16) return '';
  const h = (n: number) => b[n].toString(16).padStart(2, '0');
  return (
    `${h(3)}${h(2)}${h(1)}${h(0)}-${h(5)}${h(4)}-${h(7)}${h(6)}-` +
    `${h(8)}${h(9)}-${h(10)}${h(11)}${h(12)}${h(13)}${h(14)}${h(15)}`
  );
}

const UTF16 = new TextDecoder('utf-16le');
const ASCII = new TextDecoder('windows-1252');

/** Decodes UTF-16LE and drops everything from the first NUL onward. */
export function utf16(b: Uint8Array): string {
  const s = UTF16.decode(b);
  const nul = s.indexOf('\0');
  return nul === -1 ? s : s.slice(0, nul);
}

/**
 * Decodes UTF-16LE keeping every character, NULs included.
 *
 * Needed wherever a block holds several NUL-separated strings rather than one
 * NUL-padded field: truncating at the first NUL there would silently discard
 * everything after the first entry.
 */
export function utf16Raw(b: Uint8Array): string {
  return UTF16.decode(b);
}

/** Decodes single-byte (cp1252) and drops everything from the first NUL onward. */
export function ascii(b: Uint8Array): string {
  const s = ASCII.decode(b);
  const nul = s.indexOf('\0');
  return nul === -1 ? s : s.slice(0, nul);
}

/**
 * Sequential little-endian cursor over a buffer.
 *
 * Reads past the end return 0 / '' and set `.overran` instead of throwing, so a
 * truncated artifact still yields the records that came before the truncation.
 * Check `.overran` before trusting a record.
 */
export class Cursor {
  pos = 0;
  overran = false;
  readonly buf: Uint8Array;
  private dv: DataView;

  constructor(buf: Uint8Array, start = 0) {
    this.buf = buf;
    this.pos = start;
    this.dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  get remaining(): number {
    return Math.max(0, this.buf.length - this.pos);
  }

  private fits(n: number): boolean {
    if (this.pos < 0 || this.pos + n > this.buf.length) {
      this.overran = true;
      return false;
    }
    return true;
  }

  seek(p: number): this {
    this.pos = p;
    return this;
  }
  skip(n: number): this {
    this.pos += n;
    return this;
  }

  u8(): number {
    if (!this.fits(1)) return 0;
    return this.dv.getUint8(this.pos++);
  }
  u16(): number {
    if (!this.fits(2)) return 0;
    const v = this.dv.getUint16(this.pos, true);
    this.pos += 2;
    return v;
  }
  u32(): number {
    if (!this.fits(4)) return 0;
    const v = this.dv.getUint32(this.pos, true);
    this.pos += 4;
    return v;
  }
  i32(): number {
    if (!this.fits(4)) return 0;
    const v = this.dv.getInt32(this.pos, true);
    this.pos += 4;
    return v;
  }
  u64(): bigint {
    if (!this.fits(8)) return 0n;
    const v = this.dv.getBigUint64(this.pos, true);
    this.pos += 8;
    return v;
  }
  i64(): bigint {
    if (!this.fits(8)) return 0n;
    const v = this.dv.getBigInt64(this.pos, true);
    this.pos += 8;
    return v;
  }

  /** `n` raw bytes. Short read at EOF. */
  take(n: number): Uint8Array {
    const end = Math.min(this.pos + n, this.buf.length);
    if (!this.fits(n)) {
      const out = this.buf.subarray(Math.min(this.pos, this.buf.length), end);
      this.pos += n;
      return out;
    }
    const out = this.buf.subarray(this.pos, end);
    this.pos = end;
    return out;
  }

  /** `n` BYTES of UTF-16LE (not n characters). */
  utf16(n: number): string {
    return utf16(this.take(n));
  }
  ascii(n: number): string {
    return ascii(this.take(n));
  }

  /** UTF-16LE up to and including a NUL terminator. */
  utf16z(): string {
    const start = this.pos;
    while (this.pos + 1 < this.buf.length) {
      if (this.dv.getUint16(this.pos, true) === 0) {
        const s = utf16(this.buf.subarray(start, this.pos));
        this.pos += 2;
        return s;
      }
      this.pos += 2;
    }
    this.overran = true;
    const s = utf16(this.buf.subarray(start));
    this.pos = this.buf.length;
    return s;
  }

  filetime(): Date | null {
    return filetime(this.u64());
  }
  guid(): string {
    return guid(this.take(16));
  }
}

/** True when `buf` starts with `sig` (string is compared as single bytes). */
export function magic(buf: Uint8Array, sig: string | number[], at = 0): boolean {
  const b = typeof sig === 'string' ? [...sig].map((c) => c.charCodeAt(0)) : sig;
  if (buf.length < at + b.length) return false;
  return b.every((v, i) => buf[at + i] === v);
}
