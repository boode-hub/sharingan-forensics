/**
 * RecentFileCache.bcf: Windows 7's list of programs recently run, the
 * forerunner of Amcache.
 *
 * Ported from Eric Zimmerman's RecentFileCacheParser
 * (https://github.com/EricZimmerman/RecentFileCacheParser:
 * RecentFileCache/RecentFileCacheFile.cs and CsvOut in Program.cs).
 *
 * His Source Created/Modified/Accessed columns are the file system times of
 * the .bcf itself, which a browser is not given; they are left empty, as the
 * jump list ones are.
 */
import type { Column, ColType, Ctx, Parser, Reader, Row } from '../core/types';
import { magic } from '../core/binary';

const columns: Column[] = [
  ['SourceFile'],
  ['SourceCreated', 'date'],
  ['SourceModified', 'date'],
  ['SourceAccessed', 'date'],
  ['Filename'],
].map(([key, type = 'str']) => ({ key, label: key.replace(/([a-z])([A-Z])/g, '$1 $2'), type: type as ColType }));

const SIGNATURE = [0xfe, 0xff, 0xee, 0xff];

export const recentFileCache: Parser = {
  id: 'recentfilecache',
  name: 'RecentFileCache.bcf',
  ezTool: 'RecentFileCacheParser',
  extensions: [],
  columns,
  sniff: (head: Uint8Array) => magic(head, SIGNATURE, 0),
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    // The whole file is a few kilobytes: a list of names, nothing else.
    const b = await reader.bytes(0, reader.size);
    if (!magic(b, SIGNATURE, 0)) {
      ctx.warn(0, "invalid header; should be 'FE FF EE FF'");
      return;
    }
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const utf16 = new TextDecoder('utf-16le');
    // Names start at 0x14: a character count, the name, and a two-byte NUL.
    for (let at = 0x14; at < b.length; ) {
      if (at + 4 > b.length) {
        ctx.warn(at, 'the file ends inside a name length');
        return;
      }
      const size = dv.getInt32(at, true);
      at += 4;
      if (size < 0 || at + size * 2 > b.length) {
        ctx.warn(at - 4, `a name of ${size} characters runs past the end of the file`);
        return;
      }
      yield {
        SourceFile: reader.name,
        SourceCreated: null,
        SourceModified: null,
        SourceAccessed: null,
        Filename: utf16.decode(b.subarray(at, at + size * 2)),
      };
      at += size * 2 + 2;
    }
  },
};
