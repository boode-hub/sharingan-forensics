// Builds a small customDestinations-ms file from shortcuts already in
// fixtures/lnk (his MIT-licensed samples), laid out the way his
// CustomDestination/Entry classes read one: each category starts with a
// 16-byte header whose fourth field is the header type (0 = a named category,
// followed by a length-prefixed UTF-16 name), then its shortcuts end to end,
// then the AB FB BF BA footer.
//
// His JumpList repository carries no custom jump list, and the ones on a real
// machine are its owner's history, so this is built rather than copied. The
// shortcuts inside it are real; what the test checks is that each comes back
// with the same fields it has as a .lnk of its own.
import { readFileSync, writeFileSync } from 'node:fs';

const lnk = (name) => readFileSync(new URL(`../lnk/${name}`, import.meta.url));
const FOOTER = Buffer.from([0xab, 0xfb, 0xbf, 0xba]);

function category(headerType, name, shortcuts) {
  const head = Buffer.alloc(16);
  head.writeUInt32LE(2, 0);
  head.writeFloatLE(1.5, 4);
  head.writeUInt32LE(0, 8);
  head.writeUInt32LE(headerType, 12);
  const parts = [head];
  if (headerType === 0) {
    const n = Buffer.alloc(2);
    n.writeUInt16LE(name.length, 0);
    parts.push(n, Buffer.from(name, 'utf16le'));
  }
  return Buffer.concat([...parts, ...shortcuts, FOOTER]);
}

const file = Buffer.concat([
  category(0, 'Frequent', [lnk('WordPad.lnk'), lnk('Windows Update.lnk')]),
  category(1, '', [lnk('remote.file.xp.lnk')]),
]);
writeFileSync(new URL('9b9cdc69c1c24e2b.customDestinations-ms', import.meta.url), file);
console.log('9b9cdc69c1c24e2b.customDestinations-ms', file.length, 'bytes');
