// Builds ActivitiesCache.db, a Windows Timeline database, with SQLite itself
// (sql.js), in the shape Windows gives it: the Activity, ActivityOperation and
// Activity_PackageId tables with every column WxTCmd's classes select.
//
// No real ActivitiesCache.db can be committed: it is a record of what its
// owner did. Each row here exercises one of WxTCmd's rules, and
// src/parsers/wxtcmd.test.ts states what his tool makes of it.
//
// Schema reference: https://kacos2000.github.io/WindowsTimeline/WindowsTimeline.pdf
// (and WxTCmd's Classes/*.cs for the columns he reads).
import { writeFileSync } from 'node:fs';
import initSqlJs from 'sql.js';

const SQL = await initSqlJs();
const db = new SQL.Database();

db.run(`CREATE TABLE [Activity] ([Id] GUID PRIMARY KEY NOT NULL, [AppId] TEXT NOT NULL, [PackageIdHash] TEXT,
  [AppActivityId] TEXT, [ActivityType] INT NOT NULL, [ActivityStatus] INT NOT NULL, [ParentActivityId] GUID,
  [Tag] TEXT, [Group] TEXT, [MatchId] TEXT, [LastModifiedTime] DATETIME NOT NULL, [ExpirationTime] DATETIME NOT NULL,
  [Payload] BLOB, [Priority] INT, [IsLocalOnly] INT, [PlatformDeviceId] TEXT, [DsdDeviceId] TEXT,
  [CreatedInCloud] DATETIME, [StartTime] DATETIME, [EndTime] DATETIME, [LastModifiedOnClient] DATETIME,
  [GroupAppActivityId] TEXT, [ClipboardPayload] BLOB, [EnterpriseId] TEXT, [OriginalPayload] BLOB,
  [UserActionState] INT, [IsRead] INT, [OriginalLastModifiedOnClient] DATETIME, [GroupItems] TEXT,
  [LocalExpirationTime] DATETIME, [ETag] INT NOT NULL)`);
db.run(`CREATE TABLE [ActivityOperation] ([OperationOrder] INTEGER PRIMARY KEY ASC NOT NULL, [Id] GUID NOT NULL,
  [OperationType] INT NOT NULL, [AppId] TEXT NOT NULL, [PackageHashId] TEXT, [AppActivityId] TEXT,
  [ActivityType] INT NOT NULL, [ParentActivityId] GUID, [Tag] TEXT, [Group] TEXT, [MatchId] TEXT,
  [LastModifiedTime] DATETIME NOT NULL, [ExpirationTime] DATETIME, [Payload] BLOB, [Priority] INT,
  [CreatedTime] DATETIME, [Attachments] TEXT, [PlatformDeviceId] TEXT, [DdsDeviceId] TEXT, [CreatedInCloud] DATETIME,
  [StartTime] DATETIME, [EndTime] DATETIME, [LastModifiedOnClient] DATETIME, [CorrelationVector] TEXT,
  [GroupAppActivityId] TEXT, [ClipboardPayload] BLOB, [EnterpriseId] TEXT, [OriginalPayload] BLOB,
  [UserActionState] INT, [IsRead] INT, [OriginalLastModifiedOnClient] DATETIME, [OperationExpirationTime] DATETIME,
  [UploadAllowedByPolicy] INT, [PatchFields] BLOB, [GroupItems] TEXT, [ThrottleReleaseTime] DATETIME, [ETag] INT)`);
db.run(`CREATE TABLE [Activity_PackageId] ([ActivityId] GUID NOT NULL, [Platform] TEXT NOT NULL,
  [PackageName] TEXT NOT NULL, [ExpirationTime] DATETIME NOT NULL)`);

const T = 1700000000;
const id = (n) => Uint8Array.from({ length: 16 }, (_, i) => n * 16 + i);
const utf8 = (s) => new TextEncoder().encode(s);
const json = (v) => utf8(JSON.stringify(v));
const appId = (...apps) => JSON.stringify(apps.map(([application, platform]) => ({ application, platform })));

const insert = (table, row) => {
  const keys = Object.keys(row);
  db.run(`INSERT INTO [${table}] (${keys.map((k) => `[${k}]`).join(',')}) VALUES (${keys.map(() => '?').join(',')})`, keys.map((k) => row[k]));
};
const activity = (row) => insert('Activity', { ActivityStatus: 1, ETag: 1, LastModifiedTime: T, ExpirationTime: T + 2592000, ...row });

// Opened in Notepad: a known-folder GUID in the path, and a content URI his substitution mangles.
activity({
  Id: id(1),
  AppId: appId(['{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\notepad.exe', 'windows_win32'], ['Microsoft.Windows.Notepad', 'packageId']),
  PackageIdHash: 'hashA',
  ActivityType: 5,
  Payload: json({
    displayText: 'notes.txt',
    activationUri: 'ms-shellactivity:',
    appDisplayName: 'Notepad',
    description: 'C:\\Users\\bob\\notes.txt',
    backgroundColor: 'black',
    contentUri: 'file:///C:/Users/bob/notes%20v2.txt?VolumeId={D7A2E2B2-AAAA-BBBB-CCCC-100000000000}&ObjectId={11111111-2222-3333-4444-555555555555}',
  }),
  IsLocalOnly: 0,
  PlatformDeviceId: 'devA',
  StartTime: T,
  EndTime: T + 90061,
  LastModifiedTime: T + 10,
  LastModifiedOnClient: T + 5,
  OriginalLastModifiedOnClient: 0,
  ETag: 7,
});
// Focus time in a Store app: no win32 entry, property names in odd case, start equal to end,
// and an expiration past 2^32 that GetInt32 cuts to its low 32 bits.
activity({
  Id: id(2),
  AppId: appId(['Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge', 'windows_universal'], ['x', 'packageId']),
  ActivityType: 6,
  Payload: json({ type: 'UserEngaged', reportingApp: 'MicrosoftEdge', activeDurationSeconds: 30, userTimezone: 'Europe/London', DEVICEPLATFORM: 'Windows' }),
  IsLocalOnly: 1,
  StartTime: T + 100,
  EndTime: T + 100,
  ExpirationTime: 4294967297,
});
// No applications at all: his tool gives up on the table here; this skips the row.
activity({ Id: id(3), AppId: '[]', ActivityType: 11, Payload: json({}) });
// A copy: binary payload, clipboard text with a non-ASCII character, no end time.
activity({
  Id: id(4),
  AppId: appId(['C:\\Tools\\app.exe', 'x_exe_path']),
  ActivityType: 16,
  Payload: Uint8Array.of(1, 2, 0xff),
  ClipboardPayload: utf8('[{"content":"aGk=","formatName":"Text é"}]'),
  StartTime: T + 200,
  EndTime: 0,
});

const op = (row) => insert('ActivityOperation', { OperationType: 1, ActivityType: 5, LastModifiedTime: T, ...row });
op({
  OperationOrder: 1,
  Id: id(1),
  AppId: appId(['{F38BF404-1D43-42F2-9305-67DE0B28FC23}\\explorer.exe', 'Windows_Win32']),
  Payload: json({ displayText: 'x', description: 'd', contentUri: 'http://example.com/a+b' }),
  CreatedTime: T,
  OperationExpirationTime: T + 1,
  StartTime: 0,
  EndTime: 0,
});
op({
  OperationOrder: 2,
  Id: id(2),
  OperationType: 2,
  AppId: appId(['notepad.exe', 'windows_universal']),
  Payload: Uint8Array.of(0),
  StartTime: T,
  EndTime: T + 3661,
});
// A %-escape his UrlDecode cannot read.
op({ OperationOrder: 3, Id: id(3), AppId: appId(['a.exe', 'windows_win32']), Payload: json({ contentUri: 'file://x%zz' }) });

const pkg = (ActivityId, Platform, PackageName) => insert('Activity_PackageId', { ActivityId, Platform, PackageName, ExpirationTime: T });
pkg(id(1), 'windows_win32', '{6D809377-6AF0-444B-8957-A3773F02200E}\\Vendor\\tool.exe');
pkg(id(4), 'x_exe_path', 'C:\\Tools\\app.exe');
pkg(id(1), 'packageId', 'Microsoft.Windows.Notepad');
pkg(id(2), 'windows_universal', 'Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge');

const out = db.export();
writeFileSync(new URL('./ActivitiesCache.db', import.meta.url), out);
console.log(`ActivitiesCache.db: ${out.length} bytes`);
