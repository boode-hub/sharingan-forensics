// Builds a small SYSTEM-shaped hive holding an AppCompatCache value, once in
// the Windows 10 layout and once in the Windows 8.1 layout.
//
// A real SYSTEM hive is ten megabytes and most of it has nothing to do with
// shimcache, so the committed sample is the smallest hive that still has the
// whole path down to the value: a root key, a control set, Control, Session
// Manager and AppCompatCache. The cache blob inside it is written from the
// documented layout, which is what makes it an oracle rather than a recording
// of what the parser already does.
//
// Layout references:
//   https://github.com/EricZimmerman/AppCompatCacheParser (Windows10, Windows8x)
//   https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md
import { writeFileSync } from 'node:fs';

const HBIN_START = 4096;
const HBIN_SIZE = 16384;

const FT_EPOCH = 11644473600000n;
const ft = (iso) => (BigInt(Date.parse(iso)) + FT_EPOCH) * 10000n;
const align = (n) => Math.ceil(n / 8) * 8;

/** Lays cells out back to back, which is how a reader walks them. */
class Hbin {
  constructor() {
    this.buf = Buffer.alloc(HBIN_SIZE);
    this.buf.write('hbin', 0, 'latin1');
    this.buf.writeUInt32LE(0, 4);
    this.buf.writeUInt32LE(HBIN_SIZE, 8);
    this.buf.writeBigUInt64LE(ft('2024-01-01T00:00:00Z'), 20);
    this.at = 0x20;
  }

  /** Reserves an allocated cell and returns its offset within the hbin. */
  alloc(size) {
    const total = align(size + 4);
    const off = this.at;
    this.buf.writeInt32LE(-total, off); // negative size means in use
    this.at += total;
    return off;
  }

  /** Marks the remainder free, so the walk ends cleanly at the hbin edge. */
  seal() {
    this.buf.writeInt32LE(HBIN_SIZE - this.at, this.at);
    return this.buf;
  }
}

/**
 * The cache blob as Windows 10 writes it: a header whose first field is the
 * offset of the first record, then "10ts" records.
 */
function win10Cache(entries) {
  const records = entries.map((e) => {
    const path = Buffer.from(e.path, 'utf16le');
    // 4 signature, 4 unknown, 4 data size, 2 path size, path, 8 time,
    // 4 data size, then the data itself.
    const b = Buffer.alloc(4 + 4 + 4 + 2 + path.length + 8 + 4 + 4);
    b.write('10ts', 0, 'latin1');
    b.writeUInt32LE(0, 4);
    b.writeUInt32LE(path.length + 8 + 4 + 4, 8);
    b.writeUInt16LE(path.length, 12);
    path.copy(b, 14);
    let at = 14 + path.length;
    b.writeBigUInt64LE(e.modified ? ft(e.modified) : 0n, at);
    at += 8;
    b.writeUInt32LE(4, at); // four bytes of entry data
    at += 4;
    b.writeUInt32LE(e.executed ? 1 : 0, at); // 1 here means it ran
    return b;
  });

  const header = Buffer.alloc(0x30);
  header.writeUInt32LE(0x30, 0); // offset of the first record
  header.writeUInt32LE(entries.length, 0x24); // expected entry count
  return Buffer.concat([header, ...records]);
}

/** The cache blob as Windows 8.1 writes it: records start at 128. */
function win81Cache(entries) {
  const records = entries.map((e) => {
    const path = Buffer.from(e.path, 'utf16le');
    const b = Buffer.alloc(4 + 4 + 4 + 2 + path.length + 2 + 4 + 4 + 8 + 4 + 4);
    b.write('10ts', 0, 'latin1');
    b.writeUInt32LE(0, 4);
    b.writeUInt32LE(0, 8); // entry data size, unused by the reader
    b.writeUInt16LE(path.length, 12);
    path.copy(b, 14);
    let at = 14 + path.length;
    b.writeUInt16LE(0, at); // no package data
    at += 2;
    b.writeUInt32LE(e.executed ? 0x02 : 0x00, at); // insertion flags
    at += 4;
    b.writeUInt32LE(0, at); // shim flags
    at += 4;
    b.writeBigUInt64LE(e.modified ? ft(e.modified) : 0n, at);
    at += 8;
    b.writeUInt32LE(4, at);
    at += 4;
    b.writeUInt32LE(0, at);
    return b;
  });

  const header = Buffer.alloc(128);
  header.writeUInt32LE(128, 0);
  return Buffer.concat([header, ...records]);
}

/** A hive whose only content is the path down to an AppCompatCache value. */
function hive(cache) {
  const h = new Hbin();
  const b = h.buf;

  const names = ['ROOT', 'ControlSet001', 'Control', 'Session Manager', 'AppCompatCache'];
  const valueName = 'AppCompatCache';

  // Reserve every cell first, so a key can point at children laid out later.
  const keyAt = names.map((n) => h.alloc(0x50 + n.length));
  const listAt = names.slice(0, -1).map(() => h.alloc(4 + 8)); // one lf entry each
  const valueListAt = h.alloc(4);
  const vkAt = h.alloc(0x18 + valueName.length);
  const dataAt = h.alloc(cache.length);

  names.forEach((name, i) => {
    const at = keyAt[i];
    b.write('nk', at + 4, 'latin1');
    // Root flag on the first key; every name here is ASCII.
    b.writeUInt16LE((i === 0 ? 0x0004 : 0x0020) | 0x0020, at + 6);
    b.writeBigUInt64LE(ft('2024-03-02T04:05:06Z'), at + 8);
    b.writeUInt32LE(i === 0 ? 0xffffffff : keyAt[i - 1], at + 20); // parent
    const isLeaf = i === names.length - 1;
    b.writeUInt32LE(isLeaf ? 0 : 1, at + 24); // subkey count
    b.writeUInt32LE(isLeaf ? 0xffffffff : listAt[i], at + 32); // subkey list
    b.writeUInt32LE(isLeaf ? 1 : 0, at + 40); // value count
    b.writeUInt32LE(isLeaf ? valueListAt : 0xffffffff, at + 44);
    b.writeUInt32LE(0xffffffff, at + 48); // security
    b.writeUInt32LE(0xffffffff, at + 52); // class
    b.writeUInt16LE(name.length, at + 76);
    b.write(name, at + 80, 'latin1');

    if (!isLeaf) {
      const l = listAt[i];
      b.write('lf', l + 4, 'latin1');
      b.writeUInt16LE(1, l + 6); // one subkey
      b.writeUInt32LE(keyAt[i + 1], l + 8);
      b.write(names[i + 1].slice(0, 4).padEnd(4, ' '), l + 12, 'latin1'); // name hash
    }
  });

  b.writeUInt32LE(vkAt, valueListAt + 4);

  b.write('vk', vkAt + 4, 'latin1');
  b.writeUInt16LE(valueName.length, vkAt + 6);
  b.writeUInt32LE(cache.length, vkAt + 8);
  b.writeUInt32LE(dataAt, vkAt + 12);
  b.writeUInt32LE(3, vkAt + 16); // REG_BINARY
  b.writeUInt16LE(1, vkAt + 20); // name is ASCII
  b.write(valueName, vkAt + 24, 'latin1');

  cache.copy(b, dataAt + 4);

  const head = Buffer.alloc(HBIN_START);
  head.write('regf', 0, 'latin1');
  head.writeUInt32LE(7, 4);
  head.writeUInt32LE(7, 8); // clean: both sequence numbers agree
  head.writeBigUInt64LE(ft('2024-03-02T04:05:06Z'), 12);
  head.writeUInt32LE(1, 20);
  head.writeUInt32LE(5, 24);
  head.writeUInt32LE(0, 28);
  head.writeUInt32LE(1, 32);
  head.writeUInt32LE(keyAt[0], 36);
  head.writeUInt32LE(HBIN_SIZE, 40);
  head.writeUInt32LE(1, 44);
  Buffer.from('SYSTEM\0', 'utf16le').copy(head, 48);

  return Buffer.concat([head, h.seal()]);
}

const entries = [
  { path: 'SYSVOL\\Windows\\System32\\cmd.exe', modified: '2021-03-04T05:06:07Z', executed: true },
  { path: 'SYSVOL\\Users\\suspect\\Downloads\\tool.exe', modified: '2022-07-08T09:10:11Z', executed: true },
  { path: 'SYSVOL\\Windows\\System32\\notepad.exe', modified: '2020-01-02T03:04:05Z', executed: false },
];

const cases = {
  'SYSTEM-win10': hive(win10Cache(entries)),
  'SYSTEM-win81': hive(win81Cache(entries)),
};

for (const [name, buf] of Object.entries(cases)) {
  writeFileSync(new URL(name, import.meta.url), buf);
  console.log(name, buf.length, 'bytes');
}
