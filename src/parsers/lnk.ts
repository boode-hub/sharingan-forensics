/**
 * Windows Shortcut (.lnk) parser.
 * Format reference: [MS-SHLLINK] Microsoft Documentation
 * Replicates: Eric Zimmerman's LECmd
 */
import type { Column, Parser, Reader, Ctx, Row } from '../core/types';
import { Cursor } from '../core/binary';

const LinkCLSID = '00021401-0000-0000-C000-000000000046';

const columns: Column[] = [
  { key: 'targetPath', label: 'Target Path', type: 'str' },
  { key: 'arguments', label: 'Arguments', type: 'str' },
  { key: 'workingDirectory', label: 'Working Directory', type: 'str' },
  { key: 'description', label: 'Description', type: 'str' },
  { key: 'iconLocation', label: 'Icon Location', type: 'str' },
  { key: 'targetSize', label: 'Target Size', type: 'num' },
  { key: 'targetCreated', label: 'Target Created', type: 'date' },
  { key: 'targetModified', label: 'Target Modified', type: 'date' },
  { key: 'targetAccessed', label: 'Target Accessed', type: 'date' },
  { key: 'driveType', label: 'Drive Type', type: 'str' },
  { key: 'driveSerial', label: 'Drive Serial', type: 'str' },
  { key: 'volumeLabel', label: 'Volume Label', type: 'str' },
  { key: 'machineId', label: 'Machine ID', type: 'str' },
  { key: 'offset', label: 'Offset', type: 'num', secondary: true },
];

const DRIVE_TYPE_NAMES = ['Unknown', 'NoRootDirectory', 'Removable', 'Fixed', 'Remote', 'CD-ROM', 'RAM disk'];

function driveTypeName(v: number): string {
  return DRIVE_TYPE_NAMES[v] ?? 'Unknown';
}

function readNulTerminatedAscii(buf: Uint8Array, start: number, end: number): string {
  let i = start;
  while (i < end && buf[i] !== 0) i++;
  return String.fromCharCode(...buf.subarray(start, i));
}

function readNulTerminatedUtf16(buf: Uint8Array, start: number, end: number): string {
  let i = start;
  while (i + 1 < end && (buf[i] !== 0 || buf[i + 1] !== 0)) i += 2;
  return String.fromCharCode(...Array.from({ length: (i - start) / 2 }, (_, k) =>
    buf[start + k * 2] | (buf[start + k * 2 + 1] << 8)
  ));
}

export const lnk: Parser = {
  id: 'lnk',
  name: 'Shortcut',
  ezTool: 'LECmd',
  extensions: ['.lnk'],
  columns,
  sniff(head: Uint8Array, _filename: string): boolean {
    if (head.length < 20) return false;
    if (head[0] !== 0x4c || head[1] !== 0x00 || head[2] !== 0x00 || head[3] !== 0x00) return false;
    const clsidBytes = head.subarray(4, 20);
    const expected = [0x00, 0x02, 0x14, 0x01, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
    return clsidBytes.every((v, i) => v === expected[i]);
  },
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    const HEADER_SIZE = 76;
    const header = await reader.bytes(0, HEADER_SIZE);
    if (header.length < HEADER_SIZE) {
      ctx.warn(0, `truncated header (${header.length}/${HEADER_SIZE} bytes)`);
      return;
    }

    const c = new Cursor(header);
    const headerSize = c.u32();
    if (headerSize !== 0x4C) {
      ctx.warn(0, `invalid HeaderSize ${headerSize}, expected 0x4C`);
      return;
    }
    const linkCLSID = c.guid();
    if (linkCLSID.toLowerCase() !== LinkCLSID.toLowerCase()) {
      ctx.warn(4, `invalid LinkCLSID ${linkCLSID}`);
      return;
    }

    const linkFlags = c.u32();
    c.u32(); // FileAttributes
    const targetCreated = c.filetime();
    const targetAccessed = c.filetime();
    const targetModified = c.filetime();
    const targetSize = c.u32();
    c.i32(); // IconIndex
    c.u32(); // ShowCommand
    c.u16(); // Hotkey
    c.skip(10); // reserved

    const hasLinkTargetIDList = (linkFlags & 0x01) !== 0;
    const hasLinkInfo = (linkFlags & 0x02) !== 0;
    const hasName = (linkFlags & 0x04) !== 0;
    const hasRelativePath = (linkFlags & 0x08) !== 0;
    const hasWorkingDir = (linkFlags & 0x10) !== 0;
    const hasArguments = (linkFlags & 0x20) !== 0;
    const hasIconLocation = (linkFlags & 0x40) !== 0;
    const isUnicode = (linkFlags & 0x80) !== 0;

    let pos = HEADER_SIZE;

    // Skip ID list if present
    if (hasLinkTargetIDList) {
      if (pos + 2 > reader.size) {
        ctx.warn(pos, 'truncated IDListSize');
      } else {
        const idListSizeBuf = await reader.bytes(pos, 2);
        if (idListSizeBuf.length < 2) {
          ctx.warn(pos, 'truncated IDListSize');
        } else {
          const idListSize = new DataView(idListSizeBuf.buffer, idListSizeBuf.byteOffset, 2).getUint16(0, true);
          pos += 2 + idListSize;
        }
      }
    }

    // Parse LinkInfo if present
    let targetPath: string | null = null;
    let driveTypeStr: string | null = null;
    let driveSerialStr: string | null = null;
    let volumeLabelStr: string | null = null;
    let linkInfoEnd = pos;

    if (hasLinkInfo) {
      const linkInfoBuf = await reader.bytes(pos, Math.min(1024, reader.size - pos));
      if (linkInfoBuf.length < 4) {
        ctx.warn(pos, 'truncated LinkInfo');
      } else {
        const lc = new Cursor(linkInfoBuf);
        const linkInfoSize = lc.u32();
        if (linkInfoSize >= 28 && linkInfoBuf.length >= 28) {
          lc.u32(); // LinkInfoHeaderSize (unused)
          const linkInfoFlags = lc.u32();
          lc.skip(16); // VolumeIDOffset, LocalBasePathOffset, CommonNetworkRelativeLinkOffset, CommonPathSuffixOffset

          if ((linkInfoFlags & 0x01) !== 0) {
            // VolumeIDAndLocalBasePath
            const volumeIdOffset = new DataView(linkInfoBuf.buffer, linkInfoBuf.byteOffset + 12, 4).getUint32(0, true);
            const localBasePathOffset = new DataView(linkInfoBuf.buffer, linkInfoBuf.byteOffset + 16, 4).getUint32(0, true);
            const commonPathSuffixOffset = new DataView(linkInfoBuf.buffer, linkInfoBuf.byteOffset + 24, 4).getUint32(0, true);

            // VolumeID at LinkInfo + VolumeIDOffset
            const volIdAbs = pos + volumeIdOffset;
            const volIdBuf = await reader.bytes(volIdAbs, Math.min(64, reader.size - volIdAbs));
            if (volIdBuf.length >= 16) {
              const vc = new Cursor(volIdBuf);
              vc.u32(); // VolumeIDSize
              const dt = vc.u32();
              driveTypeStr = driveTypeName(dt);
              const serial = vc.u32();
              driveSerialStr = serial.toString(16).toUpperCase().padStart(8, '0');
              const volumeLabelOffset = new DataView(volIdBuf.buffer, volIdBuf.byteOffset + 12, 4).getUint32(0, true);

              let actualVolLabelOffset = volumeLabelOffset;
              let volLabelIsUtf16 = false;
              if (volumeLabelOffset === 0x14 && volIdBuf.length >= 20) {
                actualVolLabelOffset = new DataView(volIdBuf.buffer, volIdBuf.byteOffset + 16, 4).getUint32(0, true);
                volLabelIsUtf16 = true;
              }

              // Volume label at VolumeID + actualVolLabelOffset
              const volLabelAbs = volIdAbs + actualVolLabelOffset;
              const volLabelBuf = await reader.bytes(volLabelAbs, Math.min(64, reader.size - volLabelAbs));
              if (volLabelBuf.length > 0) {
                if (volLabelIsUtf16) {
                  volumeLabelStr = readNulTerminatedUtf16(volLabelBuf, 0, volLabelBuf.length);
                } else {
                  volumeLabelStr = readNulTerminatedAscii(volLabelBuf, 0, volLabelBuf.length);
                }
              }
            }

            // LocalBasePath + CommonPathSuffix
            if (localBasePathOffset > 0 && localBasePathOffset < linkInfoSize) {
              const localBasePathAbs = pos + localBasePathOffset;
              const localBasePathBuf = await reader.bytes(localBasePathAbs, Math.min(1024, reader.size - localBasePathAbs));
              const localBasePath = readNulTerminatedAscii(localBasePathBuf, 0, localBasePathBuf.length);

              // CommonPathSuffix starts at LinkInfo + CommonPathSuffixOffset
              let commonPathSuffix = '';
              if (commonPathSuffixOffset > 0 && commonPathSuffixOffset < linkInfoSize) {
                const cpsAbs = pos + commonPathSuffixOffset;
                const cpsBuf = await reader.bytes(cpsAbs, Math.min(512, reader.size - cpsAbs));
                commonPathSuffix = readNulTerminatedAscii(cpsBuf, 0, cpsBuf.length);
              }

              targetPath = localBasePath + commonPathSuffix;
            }
          }

          linkInfoEnd = pos + linkInfoSize;
        }
      }
    }

    pos = linkInfoEnd;

    // StringData
    let description: string | null = null;
    let relativePath: string | null = null;
    let workingDirectory: string | null = null;
    let argumentsStr: string | null = null;
    let iconLocation: string | null = null;

    async function readString(isUnicodeFlag: boolean): Promise<string | null> {
      if (pos + 2 > reader.size) return null;
      const charCountBuf = await reader.bytes(pos, 2);
      if (charCountBuf.length < 2) return null;
      const charCount = new DataView(charCountBuf.buffer, charCountBuf.byteOffset, 2).getUint16(0, true);
      pos += 2;
      const byteCount = isUnicodeFlag ? charCount * 2 : charCount;
      if (pos + byteCount > reader.size) {
        ctx.warn(pos, `truncated StringData (need ${byteCount}, have ${reader.size - pos})`);
        pos = reader.size;
        return null;
      }
      const strBuf = await reader.bytes(pos, byteCount);
      pos += isUnicodeFlag ? charCount * 2 : byteCount;
      if (isUnicodeFlag) {
        return readNulTerminatedUtf16(strBuf, 0, strBuf.length);
      } else {
        return readNulTerminatedAscii(strBuf, 0, strBuf.length);
      }
    }

    if (hasName) {
      description = await readString(isUnicode);
    }
    if (hasRelativePath) {
      relativePath = await readString(isUnicode);
    }
    if (hasWorkingDir) {
      workingDirectory = await readString(isUnicode);
    }
    if (hasArguments) {
      argumentsStr = await readString(isUnicode);
    }
    if (hasIconLocation) {
      iconLocation = await readString(isUnicode);
    }

    // ExtraData blocks
    let machineId: string | null = null;
    pos = Math.max(pos, linkInfoEnd);
    while (pos + 8 <= reader.size) {
      const extraBuf = await reader.bytes(pos, 8);
      if (extraBuf.length < 8) break;
      const ec = new Cursor(extraBuf);
      const blockSize = ec.u32();
      const signature = ec.u32();
      if (blockSize < 4 || blockSize > reader.size - pos) break;
      if (blockSize === 4) break; // terminator

      if (signature === 0xA0000003) {
        // TrackerDataBlock
        // MachineID is 16 single-byte chars at offset 16 within the block
        if (pos + 16 <= reader.size) {
          const machineIdBuf = await reader.bytes(pos + 16, 16);
          machineId = readNulTerminatedAscii(machineIdBuf, 0, machineIdBuf.length);
        }
        break;
      }
      pos += blockSize;
    }

    yield {
      targetPath,
      arguments: argumentsStr,
      workingDirectory: workingDirectory ?? relativePath,
      description,
      iconLocation,
      targetSize,
      targetCreated,
      targetModified,
      targetAccessed,
      driveType: driveTypeStr,
      driveSerial: driveSerialStr,
      volumeLabel: volumeLabelStr ?? '',
      machineId,
      offset: 0,
    };
  },
};