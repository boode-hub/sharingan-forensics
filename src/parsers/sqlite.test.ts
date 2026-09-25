import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { detect, run } from '../core/registry';
import type { Row } from '../core/types';
import { tablesFromRows } from '../ui/fields';
import { sqliteDb } from './sqlite';
import './index';

// fixtures/sqlite/CarsDB.db is his SQLMap test database (MIT), which his
// TestFiles_CarsDB map names. notes.db and notes.db-wal were written by
// SQLite itself (make-wal.py). Every expected value below came from running
// the same SQL in Python's sqlite3 (SQLite 3.50.4), not from this parser.
const file = (name: string) => bufReader(new Uint8Array(readFileSync(`fixtures/sqlite/${name}`)), name);
const byTable = (rows: Row[], t: string) => rows.filter((r) => r.table === t);

describe('SQLite (SQLECmd)', () => {
  it('is recognised by the SQLite header', async () => {
    expect((await detect(file('CarsDB.db')))?.id).toBe('sqlite');
  });

  it("runs every query of his map that names the database, one table per CSV he writes", async () => {
    const { rows, warnings } = await run(sqliteDb, file('CarsDB.db'));
    expect(warnings).toEqual([]);
    expect(tablesFromRows(rows).map((t) => [t.id, t.columns.map((c) => c.key).join(',')])).toEqual([
      ['Cars_Companies', 'Company,SourceFile'],
      ['Cars_PaymentTypeAndAmounts', 'CustomerID,PaymentType,PaymentAmount,SourceFile'],
      ['Cars_DistinctDescription', 'Description,SourceFile'],
      ['Cars_MakeModel', 'Trademark,Model,SourceFile'],
    ]);
    expect(byTable(rows, 'Cars_Companies')).toHaveLength(19);
    expect(byTable(rows, 'Cars_Companies')[0]).toMatchObject({ Company: 'Doe Enterprises', SourceFile: 'CarsDB.db' });
    const pay = byTable(rows, 'Cars_PaymentTypeAndAmounts');
    expect(pay).toHaveLength(1000);
    expect(pay[0]).toMatchObject({ CustomerID: 17, PaymentType: 'AmEx', PaymentAmount: 12565 });
    expect(pay.at(-1)).toMatchObject({ CustomerID: 27, PaymentType: 'Visa', PaymentAmount: 1852425 });
    expect(byTable(rows, 'Cars_DistinctDescription').at(-1)?.Description).toBe('\r\nWash this car in the garage');
    expect(byTable(rows, 'Cars_MakeModel')).toHaveLength(15);
    expect(tablesFromRows(rows)[1].columns.map((c) => c.type)).toEqual(['num', 'str', 'num', 'str']);
  });

  it('tries every map when none is named for the file, as his --hunt does', async () => {
    const renamed = bufReader(new Uint8Array(readFileSync('fixtures/sqlite/CarsDB.db')), 'export.sqlite');
    const { rows } = await run(sqliteDb, renamed);
    expect(byTable(rows, 'Cars_Companies')).toHaveLength(19);
  });

  it('applies a write-ahead log opened with the database, as SQLite does', async () => {
    const { rows, warnings } = await run(sqliteDb, file('notes.db'), undefined, [file('notes.db-wal')]);
    expect(rows.map((r) => [r.id, r.body, r.data, r.big])).toEqual([
      [1, 'first, edited', '0x00FF10', 1],
      [2, 'second', null, 2],
      [3, 'third', '0xCAFE', '1152921504606846976'], // past 2^53, kept exact
      [4, 'fourth', null, -5],
      [5, 'fifth', null, 3.5],
    ]);
    expect(rows[0].table).toBe('notes');
    expect(warnings.map((w) => w.message)).toEqual([
      'notes.db-wal: applied 1 committed frame(s) from the write-ahead log',
      'no SQLECmd map recognises this database; every table is listed as it is',
    ]);
  });

  it('reads the database as last checkpointed when the log is absent or damaged', async () => {
    const alone = await run(sqliteDb, file('notes.db'));
    expect(alone.rows.map((r) => [r.id, r.body])).toEqual([
      [1, 'first'],
      [2, 'second'],
    ]);
    const wal = new Uint8Array(readFileSync('fixtures/sqlite/notes.db-wal'));
    wal[40] ^= 0xff; // inside the first frame's header: its checksum no longer holds
    const damaged = await run(sqliteDb, file('notes.db'), undefined, [bufReader(wal, 'notes.db-wal')]);
    expect(damaged.rows.map((r) => r.body)).toEqual(['first', 'second']);
  });
});
