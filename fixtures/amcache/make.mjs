// Builds two small Amcache hives: one in the Windows 10+ layout
// (Root\InventoryApplicationFile and siblings) and one in the Windows 8 layout
// (Root\File\{volume}\{file} with hex-numbered values, Root\Programs).
//
// No real Amcache.hve was available to commit: the live one is locked and
// holds the owner's own program history, and EZ's repositories carry none.
// So these are written cell by cell from the regf layout and the value names
// and types Windows uses, which is what makes them an oracle rather than a
// recording of what the parser already does. The new-format hive also holds a
// deleted file key (a free nk cell whose parent is InventoryApplicationFile),
// which his Registry library attaches to its live parent.
//
// Layout references:
//   https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md
//   https://github.com/EricZimmerman/AmcacheParser (value names per key)
import { writeFileSync } from 'node:fs';

const FT_EPOCH = 11644473600000n;
const ft = (iso) => (BigInt(Date.parse(iso)) + FT_EPOCH) * 10000n;
const align = (n) => Math.ceil(n / 8) * 8;

const REG_SZ = 1;
const REG_DWORD = 4;
const REG_QWORD = 11;

const sz = (s) => ({ type: REG_SZ, data: Buffer.from(s + '\0', 'utf16le') });
const dword = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return { type: REG_DWORD, data: b };
};
const qword = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return { type: REG_QWORD, data: b };
};

class HiveWriter {
  constructor() {
    this.buf = Buffer.alloc(1 << 20);
    this.at = 0x20; // after the hbin header
  }

  /** A cell of at least `size` bytes; negative size marks it in use. */
  alloc(size, free = false) {
    const total = align(size + 4);
    const off = this.at;
    this.buf.writeInt32LE(free ? total : -total, off);
    this.at += total;
    return off;
  }

  value(name, v, free = false) {
    const vk = this.alloc(0x18 + name.length, free);
    const b = this.buf;
    b.write('vk', vk + 4, 'latin1');
    b.writeUInt16LE(name.length, vk + 6);
    if (v.data.length <= 4) {
      // Resident: the data sits in the offset field, flagged in the length.
      b.writeUInt32LE((0x80000000 | v.data.length) >>> 0, vk + 8);
      v.data.copy(b, vk + 12);
    } else {
      const data = this.alloc(v.data.length, free);
      v.data.copy(b, data + 4);
      b.writeUInt32LE(v.data.length, vk + 8);
      b.writeUInt32LE(data, vk + 12);
    }
    b.writeUInt32LE(v.type, vk + 16);
    b.writeUInt16LE(1, vk + 20); // ASCII name
    b.write(name, vk + 24, 'latin1');
    return vk;
  }

  /**
   * A key and everything below it. `k` is { name, lastWrite, values: [[name, v]],
   * subkeys: [k], deleted }. Returns the nk offset.
   */
  key(k, parent) {
    const b = this.buf;
    const free = !!k.deleted;
    const nk = this.alloc(0x50 + k.name.length, free);
    const all = (k.subkeys ?? []).map((s) => ({ s, at: this.key(s, nk) }));
    // A deleted key points at its parent, but the parent no longer lists it.
    const subs = all.filter(({ s }) => !s.deleted);
    let list = 0xffffffff;
    if (subs.length > 0) {
      list = this.alloc(4 + 8 * subs.length, free);
      b.write('lf', list + 4, 'latin1');
      b.writeUInt16LE(subs.length, list + 6);
      subs.forEach(({ s, at }, i) => {
        b.writeUInt32LE(at, list + 8 + i * 8);
        b.write(s.name.slice(0, 4).padEnd(4, '\0'), list + 12 + i * 8, 'latin1');
      });
    }
    const vals = (k.values ?? []).map(([name, v]) => this.value(name, v, free));
    let vlist = 0xffffffff;
    if (vals.length > 0) {
      vlist = this.alloc(4 * vals.length, free);
      vals.forEach((v, i) => b.writeUInt32LE(v, vlist + 4 + i * 4));
    }
    b.write('nk', nk + 4, 'latin1');
    b.writeUInt16LE((parent === undefined ? 0x0004 : 0) | 0x0020, nk + 6);
    b.writeBigUInt64LE(ft(k.lastWrite), nk + 8);
    b.writeUInt32LE(parent ?? 0xffffffff, nk + 20);
    b.writeUInt32LE(subs.length, nk + 24);
    b.writeUInt32LE(list, nk + 32);
    b.writeUInt32LE(vals.length, nk + 40);
    b.writeUInt32LE(vlist, nk + 44);
    b.writeUInt32LE(0xffffffff, nk + 48); // security
    b.writeUInt32LE(0xffffffff, nk + 52); // class
    b.writeUInt16LE(k.name.length, nk + 76);
    b.write(k.name, nk + 80, 'latin1');
    return nk;
  }

  /** The finished file: base block, then one hbin holding every cell. */
  finish(rootAt) {
    const size = Math.ceil((this.at + 8) / 4096) * 4096;
    const hbin = this.buf.subarray(0, size);
    hbin.writeInt32LE(size - this.at, this.at); // the rest is one free cell
    hbin.write('hbin', 0, 'latin1');
    hbin.writeUInt32LE(0, 4);
    hbin.writeUInt32LE(size, 8);

    const head = Buffer.alloc(4096);
    head.write('regf', 0, 'latin1');
    head.writeUInt32LE(3, 4);
    head.writeUInt32LE(3, 8); // clean
    head.writeBigUInt64LE(ft('2024-05-06T07:08:09Z'), 12);
    head.writeUInt32LE(1, 20);
    head.writeUInt32LE(5, 24);
    head.writeUInt32LE(0, 28);
    head.writeUInt32LE(1, 32);
    head.writeUInt32LE(rootAt, 36);
    head.writeUInt32LE(size, 40);
    head.writeUInt32LE(1, 44);
    // Windows keeps the tail of the hive's own path here.
    Buffer.from('ppCompat\\Programs\\Amcache.hve\0', 'utf16le').copy(head, 48);
    let x = 0;
    for (let i = 0; i < 508; i += 4) x ^= head.readUInt32LE(i);
    head.writeUInt32LE(x >>> 0, 508);
    return Buffer.concat([head, hbin]);
  }
}

const hive = (tree) => {
  const w = new HiveWriter();
  return w.finish(w.key(tree));
};

const T = '2024-05-06T07:08:09Z';

const win10 = hive({
  name: '{11517B7C-E79D-4e20-961B-75A811715ADD}',
  lastWrite: T,
  subkeys: [
    {
      name: 'Root',
      lastWrite: T,
      subkeys: [
        {
          name: 'InventoryApplication',
          lastWrite: T,
          subkeys: [
            {
              name: '0000a1b2c3d4e5f60000ffff00000000',
              lastWrite: '2023-01-02T03:04:05Z',
              values: [
                ['ProgramId', sz('0000a1b2c3d4e5f60000ffff00000000')],
                ['Name', sz('Tool Suite')],
                ['Version', sz('2.1.0')],
                ['Publisher', sz('Example Corp')],
                ['Language', dword(1033)],
                ['Source', sz('AddRemoveProgram')],
                ['Type', sz('Application')],
                ['InstallDate', sz('02/18/2021 18:46:18')],
                ['InstallDateArpLastModified', sz('02/18/2021 18:46:18')],
                ['HiddenArp', dword(0)],
                ['InboxModernApp', dword(0)],
                ['RootDirPath', sz('C:\\Program Files\\Tool Suite')],
                ['UninstallString', sz('"C:\\Program Files\\Tool Suite\\uninstall.exe"')],
                ['OSVersionAtInstallTime', sz('10.0.19045')],
                ['StoreAppType', sz('')],
                ['MsiInstallDate', sz('')],
              ],
            },
          ],
        },
        {
          name: 'InventoryApplicationFile',
          lastWrite: T,
          subkeys: [
            {
              name: 'tool.exe|8a2f1c3e5b7d9f01',
              lastWrite: '2023-01-02T03:05:00Z',
              values: [
                ['ProgramId', sz('0000a1b2c3d4e5f60000ffff00000000')],
                ['FileId', sz('00004F5B8C1D2E3F4A5B6C7D8E9FA0B1C2D3E4F5A6B7')],
                ['LowerCaseLongPath', sz('c:\\program files\\tool suite\\tool.exe')],
                ['LongPathHash', sz('tool.exe|8a2f1c3e5b7d9f01')],
                ['Name', sz('tool.exe')],
                ['OriginalFileName', sz('tool.exe')],
                ['Publisher', sz('example corp')],
                ['Version', sz('2.1.0.7')],
                ['BinFileVersion', sz('2.1.0.7')],
                ['BinaryType', sz('pe64_amd64')],
                ['ProductName', sz('tool suite')],
                ['ProductVersion', sz('2.1')],
                ['LinkDate', sz('07/13/2009 23:32:37')],
                ['BinProductVersion', sz('2.1.0.7')],
                ['Size', qword(123456)],
                ['Language', dword(0)],
                ['Usn', qword(98765432)],
                ['IsOsComponent', dword(0)],
                ['IsPeFile', dword(1)],
                ['Description', sz('Tool Suite main program')],
              ],
            },
            {
              name: 'svchost.exe|1234567890abcdef',
              lastWrite: '2022-11-12T13:14:15Z',
              values: [
                ['ProgramId', sz('0006f1e2d3c4b5a60000ffff00000000')],
                ['FileId', sz('0000AABBCCDDEEFF00112233445566778899AABBCC')],
                ['LowerCaseLongPath', sz('c:\\windows\\system32\\svchost.exe')],
                ['Name', sz('svchost.exe')],
                ['Size', sz('0x000000000000c6f8')],
                ['IsOsComponent', dword(1)],
                ['IsPeFile', dword(1)],
                ['LinkDate', sz('13/45/2010 99:00:00')],
                ['Language', dword(1033)],
                ['BrandNewValue', sz('something Windows added later')],
              ],
            },
            {
              name: 'dropper.exe|ffff0000ffff0000',
              lastWrite: '2024-02-03T04:05:06Z',
              deleted: true,
              values: [
                ['FileId', sz('0000DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF')],
                ['LowerCaseLongPath', sz('c:\\users\\suspect\\appdata\\local\\temp\\dropper.exe')],
                ['Name', sz('dropper.exe')],
                ['Size', qword(4096)],
              ],
            },
          ],
        },
        {
          name: 'InventoryApplicationShortcut',
          lastWrite: T,
          subkeys: [
            {
              name: 'c:|programdata|microsoft|windows|start menu|programs|tool suite.lnk',
              lastWrite: '2023-01-02T03:06:00Z',
              values: [['ShortcutPath', sz('c:\\programdata\\microsoft\\windows\\start menu\\programs\\tool suite.lnk')]],
            },
          ],
        },
        {
          name: 'InventoryDeviceContainer',
          lastWrite: T,
          subkeys: [
            {
              name: '{00000000-0000-0000-ffff-ffffffffffff}',
              lastWrite: '2023-03-04T05:06:07Z',
              values: [
                ['Categories', sz('Computer.Desktop')],
                ['FriendlyName', sz('DESKTOP-TEST')],
                ['IsActive', dword(1)],
                ['IsConnected', dword(1)],
                ['IsMachineContainer', dword(1)],
                ['IsNetworked', dword(0)],
                ['IsPaired', dword(0)],
                ['Manufacturer', sz('Example Hardware')],
                ['ModelName', sz('Model 9')],
                ['PrimaryCategory', sz('Computer.Desktop')],
                ['State', sz('0')],
              ],
            },
          ],
        },
        {
          name: 'InventoryDevicePnp',
          lastWrite: T,
          subkeys: [
            {
              name: 'usb/vid_0781&pid_5583/4c530001',
              lastWrite: '2023-04-05T06:07:08Z',
              values: [
                ['BusReportedDescription', sz('Ultra Fit')],
                ['Class', sz('USB')],
                ['ClassGuid', sz('{36fc9e60-c465-11cf-8056-444553540000}')],
                ['COMPID', sz('USB\\Class_08&SubClass_06&Prot_50')],
                ['ContainerId', sz('{1a2b3c4d-0000-0000-0000-000000000000}')],
                ['Description', sz('USB Mass Storage Device')],
                ['DeviceState', sz('96')],
                ['DriverId', sz('0000abcdef')],
                ['DriverName', sz('usbstor.inf')],
                ['Enumerator', sz('usb')],
                ['HWID', sz('USB\\VID_0781&PID_5583&REV_0100')],
                ['Inf', sz('usbstor.inf')],
                ['Manufacturer', sz('Compatible USB storage device')],
                ['MatchingID', sz('usb\\class_08&subclass_06&prot_50')],
                ['Model', sz('USB Mass Storage Device')],
                ['ParentId', sz('USB\\ROOT_HUB30\\4&1234&0&0')],
                ['ProblemCode', sz('0')],
                ['Provider', sz('Microsoft')],
                ['Service', sz('USBSTOR')],
                ['STACKID', sz('\\Driver\\USBSTOR')],
              ],
            },
          ],
        },
        {
          name: 'InventoryDriverBinary',
          lastWrite: T,
          subkeys: [
            {
              name: 'c:/windows/system32/drivers/usbstor.sys',
              lastWrite: '2023-05-06T07:08:09Z',
              values: [
                ['DriverCheckSum', dword(0xf0001234)],
                ['DriverCompany', sz('Microsoft Corporation')],
                ['DriverId', sz('00001111222233334444555566667777888899990000')],
                ['DriverInBox', dword(1)],
                ['DriverIsKernelMode', dword(1)],
                ['DriverLastWriteTime', sz('12/07/2019 09:08:57')],
                ['DriverName', sz('usbstor.sys')],
                ['DriverSigned', dword(1)],
                ['DriverTimeStamp', dword(1575709737)],
                ['DriverType', sz('0x0000000000000001')],
                ['DriverVersion', sz('10.0.19041.1')],
                ['ImageSize', dword(94208)],
                ['Inf', sz('usbstor.inf')],
                ['Product', sz('Microsoft Windows Operating System')],
                ['ProductVersion', sz('10.0.19041.1')],
                ['Service', sz('USBSTOR')],
                ['WdfVersion', sz('0.0')],
              ],
            },
          ],
        },
        {
          name: 'InventoryDriverPackage',
          lastWrite: T,
          subkeys: [
            {
              name: 'usbstor.inf_amd64_0123456789abcdef',
              lastWrite: '2023-06-07T08:09:10Z',
              values: [
                ['Class', sz('USB')],
                ['ClassGuid', sz('{36fc9e60-c465-11cf-8056-444553540000}')],
                ['Date', sz('06/21/2006 00:00:00')],
                ['Directory', sz('C:\\Windows\\System32\\DriverStore\\FileRepository\\usbstor.inf_amd64_0123456789abcdef')],
                ['DriverInBox', dword(1)],
                ['Hwids', sz('USB\\Class_08&SubClass_06&Prot_50')],
                ['Inf', sz('usbstor.inf')],
                ['Provider', sz('Microsoft')],
                ['SubmissionId', sz('')],
                ['SYSFILE', sz('usbstor.sys')],
                ['Version', sz('10.0.19041.1')],
              ],
            },
          ],
        },
      ],
    },
  ],
});

// Windows 8: values under a File subkey are numbered in hex.
const win8 = hive({
  name: '{11517B7C-E79D-4e20-961B-75A811715ADD}',
  lastWrite: T,
  subkeys: [
    {
      name: 'Root',
      lastWrite: T,
      subkeys: [
        {
          name: 'File',
          lastWrite: T,
          subkeys: [
            {
              name: '{1d5c2d6e-0000-0000-0000-100000000000}',
              lastWrite: '2014-01-02T03:04:05Z',
              subkeys: [
                {
                  // Sequence 3, entry 0x1a2b: his split of the name gives both.
                  name: '300001a2b',
                  lastWrite: '2014-01-02T03:04:06Z',
                  values: [
                    ['0', sz('Tool Suite')],
                    ['1', sz('Example Corp')],
                    ['5', sz('2.1.0.7')],
                    ['6', dword(123456)],
                    ['c', sz('Tool Suite main program')],
                    ['f', dword(1247527957)],
                    ['11', qword(ft('2013-12-01T10:00:00Z'))],
                    ['12', qword(ft('2013-11-30T09:00:00Z'))],
                    ['15', sz('C:\\Program Files\\Tool Suite\\tool.exe')],
                    ['17', qword(ft('2013-12-02T11:00:00Z'))],
                    ['100', sz('0000f00dcafe0000')],
                    ['101', sz('00004F5B8C1D2E3F4A5B6C7D8E9FA0B1C2D3E4F5A6B7')],
                  ],
                },
                {
                  name: '10000f00d',
                  lastWrite: '2014-01-03T00:00:00Z',
                  values: [
                    ['15', sz('C:\\Users\\bob\\Downloads\\unknown.bin')],
                    ['101', sz('0000AABBCCDDEEFF00112233445566778899AABBCC')],
                  ],
                },
                {
                  // No path: he skips it.
                  name: '20000beef',
                  lastWrite: '2014-01-04T00:00:00Z',
                  values: [['0', sz('No Path Product')]],
                },
              ],
            },
          ],
        },
        {
          name: 'Programs',
          lastWrite: T,
          subkeys: [
            {
              name: '0000f00dcafe0000',
              lastWrite: '2014-01-01T00:00:00Z',
              values: [
                ['0', sz('Tool Suite')],
                ['1', sz('2.1')],
                ['2', sz('Example Corp')],
                ['3', dword(1033)],
                ['6', sz('C:\\Setup\\')],
                ['a', dword(1388534400)],
                ['b', dword(1388620800)],
                ['d', sz('C:\\Program Files\\Tool Suite')],
                ['13', dword(7)],
                ['14', dword(8)],
                ['Files', sz('{1d5c2d6e-0000-0000-0000-100000000000}@300001a2b')],
              ],
            },
          ],
        },
      ],
    },
  ],
});

writeFileSync(new URL('Amcache-win10.hve', import.meta.url), win10);
writeFileSync(new URL('Amcache-win8.hve', import.meta.url), win8);
console.log('Amcache-win10.hve', win10.length, 'bytes; Amcache-win8.hve', win8.length, 'bytes');
