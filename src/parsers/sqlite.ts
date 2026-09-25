/**
 * SQLite databases, read as SQLECmd reads them: every one of his map files
 * whose IdentifyQuery recognises the database runs its queries, and each
 * query's results are one table (one CSV in his output).
 *
 * Ported from Eric Zimmerman's SQLECmd (https://github.com/EricZimmerman/SQLECmd:
 * SQLECmd/Program.cs ProcessFile, SQLMap/SQLMap.cs, SQLMap/MapFile.cs); the
 * maps themselves are generated into ./sqlite/maps.ts by scripts/gen-sqlmaps.mjs.
 *
 * The queries run on SQLite itself (sql.js, SQLite compiled to WebAssembly),
 * the same engine his tool drives, so a query gives the rows it gives him.
 * Where he differs by default:
 *  - A database whose name no map names is tried against every map, as his
 *    --hunt does, rather than left unprocessed.
 *  - A database no map recognises has each of its tables listed whole,
 *    rather than only their names in his log.
 *
 * A write-ahead log opened with the database (its "-wal" file) is applied as
 * SQLite applies it on open: every frame up to the last valid commit, checked
 * against the WAL's salts and checksums (https://sqlite.org/fileformat2.html#walformat).
 */
import type { Database, SqlJsStatic, SqlValue } from 'sql.js';
import type { Ctx, Parser, Reader, Row } from '../core/types';
import { magic } from '../core/binary';

let engine: Promise<SqlJsStatic> | null = null;

/** SQLite, compiled from bytes bundled with the app: nothing is fetched. */
function sqlite(): Promise<SqlJsStatic> {
  engine ??= (async () => {
    const [{ default: init }, { default: wasm }] = await Promise.all([
      import('sql.js'),
      import('sql.js/dist/sql-wasm.wasm?inline'),
    ]);
    const bytes = Uint8Array.from(atob(wasm.slice(wasm.indexOf(',') + 1)), (c) => c.charCodeAt(0));
    return init({
      instantiateWasm: (imports, done) => {
        WebAssembly.instantiate(bytes, imports).then((r) => done(r.instance));
        return {};
      },
    });
  })();
  return engine;
}

/** SQLite's WAL checksum: pairs of 32-bit words, in the byte order the WAL's magic names. */
function walChecksum(b: Uint8Array, bigEndian: boolean, s0: number, s1: number): [number, number] {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  for (let i = 0; i + 8 <= b.length; i += 8) {
    s0 = (s0 + dv.getUint32(i, !bigEndian) + s1) >>> 0;
    s1 = (s1 + dv.getUint32(i + 4, !bigEndian) + s0) >>> 0;
  }
  return [s0, s1];
}

/** The database as SQLite would see it with this WAL beside it. */
export function applyWal(db: Uint8Array, wal: Uint8Array, warn: (message: string) => void): Uint8Array {
  if (wal.length < 32) return db;
  const hv = new DataView(wal.buffer, wal.byteOffset, wal.byteLength);
  const walMagic = hv.getUint32(0);
  if (walMagic !== 0x377f0682 && walMagic !== 0x377f0683) {
    warn('the -wal file is not a SQLite write-ahead log; the database is read without it');
    return db;
  }
  const big = walMagic === 0x377f0683;
  const pageSize = hv.getUint32(8);
  const salt1 = hv.getUint32(16);
  const salt2 = hv.getUint32(20);
  let [s0, s1] = walChecksum(wal.subarray(0, 24), big, 0, 0);
  if (s0 !== hv.getUint32(24) || s1 !== hv.getUint32(28) || pageSize < 512 || pageSize > 65536) {
    warn('the write-ahead log header is not valid, so SQLite would ignore the log; so does this');
    return db;
  }
  // A frame counts once a later frame (or itself) commits the transaction it belongs to.
  const committed = new Map<number, number>();
  const pending = new Map<number, number>();
  let pages = 0;
  let frames = 0;
  for (let at = 32; at + 24 + pageSize <= wal.length; at += 24 + pageSize) {
    const page = hv.getUint32(at);
    const size = hv.getUint32(at + 4);
    if (page === 0 || hv.getUint32(at + 8) !== salt1 || hv.getUint32(at + 12) !== salt2) break;
    [s0, s1] = walChecksum(wal.subarray(at, at + 8), big, s0, s1);
    [s0, s1] = walChecksum(wal.subarray(at + 24, at + 24 + pageSize), big, s0, s1);
    if (s0 !== hv.getUint32(at + 16) || s1 !== hv.getUint32(at + 20)) break;
    pending.set(page, at + 24);
    frames++;
    if (size !== 0) {
      for (const [p, o] of pending) committed.set(p, o);
      pending.clear();
      pages = size;
    }
  }
  if (pending.size > 0) warn(`the last ${pending.size} page(s) in the write-ahead log belong to a transaction that never committed, and are not applied`);
  if (pages === 0) return db;
  const out = new Uint8Array(pages * pageSize);
  out.set(db.subarray(0, Math.min(db.length, out.length)));
  for (const [p, o] of committed) if (p <= pages) out.set(wal.subarray(o, o + pageSize), (p - 1) * pageSize);
  warn(`applied ${frames - pending.size} committed frame(s) from the write-ahead log`);
  return out;
}

/** A value as his CSV writes it: blobs as CsvHelper's "0x" hex, integers exact. */
function value(v: SqlValue): unknown {
  if (typeof v === 'bigint') return v >= Number.MIN_SAFE_INTEGER && v <= Number.MAX_SAFE_INTEGER ? Number(v) : v.toString();
  if (v instanceof Uint8Array) return `0x${Array.from(v, (x) => x.toString(16).toUpperCase().padStart(2, '0')).join('')}`;
  return v;
}

const quoteIdent = (s: string) => `"${s.replaceAll('"', '""')}"`;

export const isSqlite = (head: Uint8Array) => magic(head, 'SQLite format 3\0', 0);

/**
 * The database as his tools see it when they open it in place: with its
 * write-ahead log, when one was opened alongside, already applied. Null (and
 * a warning) when SQLite cannot open it.
 */
export async function openSqlite(reader: Reader, ctx: Ctx): Promise<Database | null> {
  // ponytail: the whole database is held in memory, twice while SQLite copies it in; fine for browser
  // and Windows databases (tens to hundreds of MB), a paged VFS if multi-GB ones turn up.
  let bytes: Uint8Array = (await reader.bytes(0, reader.size)).slice();
  const wal = ctx.siblings?.find((s) => /-wal$/i.test(s.name));
  if (wal) bytes = applyWal(bytes, await wal.bytes(0, wal.size), (m) => ctx.warn(0, `${wal.name}: ${m}`));
  // A WAL-mode header makes SQLite look for a -wal of its own; with the log
  // already applied (or absent), the file is read as a plain database.
  if (bytes[18] === 2) bytes[18] = 1;
  if (bytes[19] === 2) bytes[19] = 1;
  const SQL = await sqlite();
  try {
    return new SQL.Database(bytes);
  } catch (e) {
    ctx.warn(0, `SQLite could not open the database: ${(e as Error).message}`);
    return null;
  }
}

export const sqliteDb: Parser = {
  id: 'sqlite',
  name: 'SQLite database',
  ezTool: 'SQLECmd',
  extensions: [],
  columns: [],
  sniff: isSqlite,
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    const [db, { SQL_MAPS }] = await Promise.all([openSqlite(reader, ctx), import('./sqlite/maps')]);
    if (!db) return;
    const source = reader.name;
    const scalar = (sql: string): string | null => {
      const st = db.prepare(sql);
      try {
        return st.step() ? String(value(st.get(null, { useBigInt: true })[0]) ?? '') : null;
      } finally {
        st.free();
      }
    };
    const rows = function* (sql: string, table: string, drop: Set<string>) {
      const st = db.prepare(sql);
      try {
        const names = st.getColumnNames();
        while (st.step()) {
          const vals = st.get(null, { useBigInt: true });
          const row: Row = {};
          // Blob columns a map names are saved to files by his tool and left out of its CSV.
          names.forEach((n, i) => {
            if (!(drop.has(n.toLowerCase()) && vals[i] instanceof Uint8Array)) row[n] = value(vals[i]);
          });
          row.SourceFile = source;
          row.table = table;
          yield row;
        }
      } finally {
        st.free();
      }
    };

    try {
      const base = (source.split(/[\\/]/).pop() ?? source).toLowerCase();
      const named = SQL_MAPS.filter((m) => m.fileName.toLowerCase() === base);
      let matched = false;
      for (const map of named.length > 0 ? named : SQL_MAPS) {
        let id: string | null;
        try {
          id = scalar(map.identifyQuery);
        } catch {
          continue; // an identify query naming tables this database lacks
        }
        if (id?.toLowerCase() !== map.identifyValue.toLowerCase()) continue;
        matched = true;
        for (const q of map.queries) {
          if (ctx.signal?.aborted) return;
          try {
            yield* rows(q.query, `${map.csvPrefix}_${q.baseFileName}`, new Set(q.blobColumns.map((c) => c.toLowerCase())));
          } catch (e) {
            ctx.warn(0, `${map.description}, query "${q.name}": ${(e as Error).message}`);
          }
        }
      }
      if (!matched) {
        ctx.warn(0, 'no SQLECmd map recognises this database; every table is listed as it is');
        const names: string[] = [];
        for (const r of rows("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name", '', new Set())) names.push(String(r.name));
        for (const n of names) {
          try {
            yield* rows(`SELECT * FROM ${quoteIdent(n)}`, n, new Set());
          } catch (e) {
            ctx.warn(0, `table ${n}: ${(e as Error).message}`);
          }
        }
      }
    } finally {
      db.close();
    }
  },
};
