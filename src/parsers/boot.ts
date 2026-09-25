/**
 * $Boot, the NTFS boot sector: the volume's geometry, where $MFT and
 * $MFTMirr start, and its serial number.
 *
 * Ported from Eric Zimmerman's Boot library (https://github.com/EricZimmerman/MFT:
 * Boot/Boot.cs) and MFTECmd's ProcessBoot and BootOut
 * (https://github.com/EricZimmerman/MFTECmd).
 */
import type { Column, ColType, Ctx, Parser, Reader, Row } from '../core/types';
import { magic } from '../core/binary';

// BootOut, automapped in declaration order.
const columns: Column[] = [
  ['EntryPoint'],
  ['Signature'],
  ['BytesPerSector', 'num'],
  ['SectorsPerCluster', 'num'],
  ['ClusterSize', 'num'],
  ['ReservedSectors', 'num'],
  ['TotalSectors', 'num'],
  ['MftClusterBlockNumber', 'num'],
  ['MftMirrClusterBlockNumber', 'num'],
  ['MftEntrySize', 'num'],
  ['IndexEntrySize', 'num'],
  ['VolumeSerialNumberRaw'],
  ['VolumeSerialNumber'],
  ['VolumeSerialNumber32'],
  ['VolumeSerialNumber32Reverse'],
  ['SectorSignature'],
  ['SourceFile'],
].map(([key, type = 'str']) => ({ key, label: key.replace(/([a-z0-9])([A-Z])/g, '$1 $2'), type: type as ColType }));

const hex2 = (b: number) => b.toString(16).toUpperCase().padStart(2, '0');

/** His GetSizeAsBytes: a count of clusters, or when the byte is negative, 2 to the power of its magnitude. */
const sizeAsBytes = (size: number, cluster: number) => (size <= 127 ? size * cluster : 2 ** (256 - size));

export const boot: Parser = {
  id: 'boot',
  name: '$Boot',
  ezTool: 'MFTECmd',
  extensions: [],
  columns,
  sniff: (head: Uint8Array) => magic(head, 'NTFS', 3),
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    // He reads the first sector into a zeroed buffer, however short the file.
    const b = new Uint8Array(512);
    b.set(await reader.bytes(0, 512));
    const dv = new DataView(b.buffer);
    const signature = dv.getUint16(510, true);
    if (signature !== 0xaa55) {
      ctx.warn(510, `expected signature (0x55 0xAA) not found at offset 0x1FE: ${hex2(b[510])} ${hex2(b[511])}`);
    }
    const bytesPerSector = dv.getInt16(11, true);
    const sectorsPerCluster = b[13];
    const cluster = bytesPerSector * sectorsPerCluster;
    const serial = [...b.subarray(72, 80)].map(hex2);
    yield {
      EntryPoint: `0x${hex2(b[0])} 0x${hex2(b[1])} 0x${hex2(b[2])}`,
      Signature: [...b.subarray(3, 11)].map((c) => (c < 0x80 ? String.fromCharCode(c) : '?')).join(''),
      BytesPerSector: bytesPerSector,
      SectorsPerCluster: sectorsPerCluster,
      ClusterSize: cluster,
      ReservedSectors: dv.getInt16(14, true),
      TotalSectors: Number(dv.getBigInt64(40, true)),
      MftClusterBlockNumber: Number(dv.getBigInt64(48, true)),
      MftMirrClusterBlockNumber: Number(dv.getBigInt64(56, true)),
      MftEntrySize: sizeAsBytes(b[64], cluster),
      IndexEntrySize: sizeAsBytes(b[68], cluster),
      // A long formatted "X": two's complement when negative.
      VolumeSerialNumberRaw: `0x${BigInt.asUintN(64, dv.getBigInt64(72, true)).toString(16).toUpperCase()}`,
      VolumeSerialNumber: serial.join(' '),
      VolumeSerialNumber32: serial.slice(0, 4).join(' '),
      VolumeSerialNumber32Reverse: serial.slice(0, 4).reverse().join(' '),
      SectorSignature: `${hex2(b[510])} ${hex2(b[511])}`,
      SourceFile: reader.name,
    };
  },
};
