import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { detect, run } from '../core/registry';
import { boot } from './boot';
import './index';

// fixtures/boot/$Boot is the sample from his MFT test corpus (MIT). The
// expected values were read off its hex by hand:
//   0x0B 00 02 -> 512 bytes/sector, 0x0D 08 -> 8 sectors/cluster,
//   0x28 ff cf 8a 3b -> 998,952,959 sectors, 0x30 00 00 0c -> $MFT at 786,432,
//   0x38 02 -> $MFTMirr at 2, 0x40 f6 -> 2^(256-246) = 1024-byte FILE records,
//   0x44 01 -> one 4096-byte cluster per index record, 0x48 d7 65 d1 1e 98 d1 1e e2.
const buf = new Uint8Array(readFileSync('fixtures/boot/$Boot'));

describe('$Boot (MFTECmd)', () => {
  it('is recognised by the NTFS signature at offset 3', async () => {
    expect((await detect(bufReader(buf, 'sector0.bin')))?.id).toBe('boot');
  });

  it('writes his BootOut row', async () => {
    const { rows, warnings } = await run(boot, bufReader(buf, '$Boot'));
    expect(warnings).toEqual([]);
    expect(rows).toEqual([
      {
        EntryPoint: '0xEB 0x52 0x90',
        Signature: 'NTFS    ',
        BytesPerSector: 512,
        SectorsPerCluster: 8,
        ClusterSize: 4096,
        ReservedSectors: 0,
        TotalSectors: 998952959,
        MftClusterBlockNumber: 786432,
        MftMirrClusterBlockNumber: 2,
        MftEntrySize: 1024,
        IndexEntrySize: 4096,
        VolumeSerialNumberRaw: '0xE21ED1981ED165D7',
        VolumeSerialNumber: 'D7 65 D1 1E 98 D1 1E E2',
        VolumeSerialNumber32: 'D7 65 D1 1E',
        VolumeSerialNumber32Reverse: '1E D1 65 D7',
        SectorSignature: '55 AA',
        SourceFile: '$Boot',
      },
    ]);
  });

  it('still writes the row when the sector signature is wrong, and says so', async () => {
    const bad = buf.slice(0, 512);
    bad[511] = 0;
    const { rows, warnings } = await run(boot, bufReader(bad, '$Boot'));
    expect(rows[0].SectorSignature).toBe('55 00');
    expect(warnings[0].message).toMatch(/0x55 0xAA\) not found/);
  });
});
