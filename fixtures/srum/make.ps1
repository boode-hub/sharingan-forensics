# Writes SRUDB.dat with Windows' own ESE engine (esent.dll, through the
# ManagedEsent interop Windows ships in the GAC): the SRUM tables and columns
# SrumECmd reads, with a few rows each, 4 KB pages as SRUM uses.
#
#   powershell -ExecutionPolicy Bypass -File fixtures/srum/make.ps1
#
# esent stamps each database with its own signature and times, so the bytes
# differ run to run while the contents do not; CI does not regenerate it.
# src/parsers/srum.test.ts states what SrumECmd writes for each row.
$ErrorActionPreference = 'Stop'
[void][Reflection.Assembly]::LoadWithPartialName('Microsoft.Isam.Esent.Interop')
$Api = [Microsoft.Isam.Esent.Interop.Api]
$T = [Microsoft.Isam.Esent.Interop.JET_coltyp]
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = Join-Path ([IO.Path]::GetTempPath()) ('srumfix-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory $work | Out-Null
$db = Join-Path $work 'SRUDB.dat'

[Microsoft.Isam.Esent.Interop.SystemParameters]::DatabasePageSize = 4096
$inst = New-Object Microsoft.Isam.Esent.Interop.Instance ('srumfix' + [guid]::NewGuid().ToString('N').Substring(0, 6))
$inst.Parameters.CircularLog = $true
$inst.Parameters.NoInformationEvent = $true
$inst.Parameters.LogFileDirectory = "$work\"
$inst.Parameters.SystemDirectory = "$work\"
$inst.Parameters.TempDirectory = "$work\"
$inst.Init()
$ses = New-Object Microsoft.Isam.Esent.Interop.Session ($inst)
$dbid = New-Object Microsoft.Isam.Esent.Interop.JET_DBID
$Api::JetCreateDatabase($ses, $db, $null, [ref]$dbid, [Microsoft.Isam.Esent.Interop.CreateDatabaseGrbit]::OverwriteExisting)

function New-Table($name, $cols) {
  $Api::JetBeginTransaction($ses)
  $tid = New-Object Microsoft.Isam.Esent.Interop.JET_TABLEID
  $Api::JetCreateTable($ses, $dbid, $name, 0, 100, [ref]$tid)
  $ids = @{}
  foreach ($c in $cols) {
    $def = New-Object Microsoft.Isam.Esent.Interop.JET_COLUMNDEF
    $def.coltyp = $c[1]
    if ($c[0] -eq 'AutoIncId') { $def.grbit = [Microsoft.Isam.Esent.Interop.ColumndefGrbit]::ColumnAutoincrement }
    $cid = New-Object Microsoft.Isam.Esent.Interop.JET_COLUMNID
    $Api::JetAddColumn($ses, $tid, $c[0], $def, $null, 0, [ref]$cid)
    $ids[$c[0]] = $cid
  }
  $key = if ($ids.ContainsKey('AutoIncId')) { "+AutoIncId`0`0" } else { "+IdIndex`0`0" }
  $Api::JetCreateIndex($ses, $tid, 'PK', [Microsoft.Isam.Esent.Interop.CreateIndexGrbit]::IndexPrimary, $key, $key.Length, 100)
  $Api::JetCommitTransaction($ses, [Microsoft.Isam.Esent.Interop.CommitTransactionGrbit]::None)
  return @{ tid = $tid; ids = $ids }
}

function Add-Row($t, $values) {
  $Api::JetBeginTransaction($ses)
  $Api::JetPrepareUpdate($ses, $t.tid, [Microsoft.Isam.Esent.Interop.JET_prep]::Insert)
  foreach ($k in $values.Keys) { $Api::SetColumn($ses, $t.tid, $t.ids[$k], $values[$k]) }
  $Api::JetUpdate($ses, $t.tid)
  $Api::JetCommitTransaction($ses, [Microsoft.Isam.Esent.Interop.CommitTransactionGrbit]::None)
}

function Sid($text) {
  $parts = $text.Split('-')
  $subs = $parts[3..($parts.Length - 1)]
  $b = New-Object byte[] (8 + 4 * $subs.Length)
  $b[0] = [byte]$parts[1]; $b[1] = [byte]$subs.Length; $b[7] = [byte]$parts[2]
  for ($i = 0; $i -lt $subs.Length; $i++) { [BitConverter]::GetBytes([uint32]$subs[$i]).CopyTo($b, 8 + 4 * $i) }
  return , $b
}
$utf16 = { param($s) , [Text.Encoding]::Unicode.GetBytes($s + "`0") }
$ts = [DateTime]::SpecifyKind([DateTime]'2026-09-20T10:00:00', 'Utc')
$ft = { param($iso) [DateTime]::Parse($iso, $null, 'AdjustToUniversal,AssumeUniversal').ToFileTimeUtc() }

$idmap = New-Table 'SruDbIdMapTable' @(@('IdType', $T::UnsignedByte), @('IdIndex', $T::Long), @('IdBlob', $T::LongBinary))
Add-Row $idmap @{ IdType = [byte]0; IdIndex = 1; IdBlob = (& $utf16 '\Device\HarddiskVolume3\Windows\System32\svchost.exe') }
Add-Row $idmap @{ IdType = [byte]1; IdIndex = 2; IdBlob = (& $utf16 'DnsCache') }
Add-Row $idmap @{ IdType = [byte]2; IdIndex = 3; IdBlob = (& $utf16 '!!Microsoft.WindowsCalculator_8wekyb3d8bbwe!App!2026/09/01:10:20:30!0!Calculator') }
Add-Row $idmap @{ IdType = [byte]3; IdIndex = 4; IdBlob = (Sid 'S-1-5-18') }
Add-Row $idmap @{ IdType = [byte]3; IdIndex = 5; IdBlob = (Sid 'S-1-5-21-111-222-333-1001') }
Add-Row $idmap @{ IdType = [byte]3; IdIndex = 6; IdBlob = (Sid 'S-1-5-21-111-222-333-500') }
# Longer than a page: esent stores it as a separate long value.
Add-Row $idmap @{ IdType = [byte]0; IdIndex = 7; IdBlob = (& $utf16 ('\Device\HarddiskVolume3\Tools\' + ('a' * 3000) + '.exe')) }

$common = @(@('AutoIncId', $T::Long), @('TimeStamp', $T::DateTime), @('AppId', $T::Long), @('UserId', $T::Long))
$net = New-Table '{973F5D5C-1D90-4944-BE8E-24B94231A174}' ($common + @(@('InterfaceLuid', $T::Currency), @('L2ProfileId', $T::Long), @('L2ProfileFlags', $T::Long), @('BytesSent', $T::Currency), @('BytesRecvd', $T::Currency)))
Add-Row $net @{ TimeStamp = $ts; AppId = 1; UserId = 4; InterfaceLuid = (([long]71 -shl 48) + 1); L2ProfileId = 5; L2ProfileFlags = 0; BytesSent = [long]1234567890123; BytesRecvd = [long]42 }
Add-Row $net @{ TimeStamp = $ts.AddMinutes(1); AppId = 7; UserId = 5; InterfaceLuid = ([long]6 -shl 48); L2ProfileId = 0; L2ProfileFlags = 3; BytesSent = [long]0; BytesRecvd = [long]7 }

$res = New-Table '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}' ($common + @(
    @('ForegroundCycleTime', $T::Currency), @('BackgroundCycleTime', $T::Currency), @('FaceTime', $T::Currency),
    @('ForegroundContextSwitches', $T::Long), @('BackgroundContextSwitches', $T::Long),
    @('ForegroundBytesRead', $T::Currency), @('ForegroundBytesWritten', $T::Currency),
    @('ForegroundNumReadOperations', $T::Long), @('ForegroundNumWriteOperations', $T::Long), @('ForegroundNumberOfFlushes', $T::Long),
    @('BackgroundBytesRead', $T::Currency), @('BackgroundBytesWritten', $T::Currency),
    @('BackgroundNumReadOperations', $T::Long), @('BackgroundNumWriteOperations', $T::Long), @('BackgroundNumberOfFlushes', $T::Long)))
Add-Row $res @{ TimeStamp = $ts; AppId = 3; UserId = 6; ForegroundCycleTime = [long]100; BackgroundCycleTime = [long]200; FaceTime = [long]300; ForegroundContextSwitches = 4; BackgroundContextSwitches = 5; ForegroundBytesRead = [long]600; ForegroundBytesWritten = [long]700; ForegroundNumReadOperations = 8; ForegroundNumWriteOperations = 9; ForegroundNumberOfFlushes = 10; BackgroundBytesRead = [long]1100; BackgroundBytesWritten = [long]1200; BackgroundNumReadOperations = 13; BackgroundNumWriteOperations = 14; BackgroundNumberOfFlushes = 15 }

$conn = New-Table '{DD6636C4-8929-4683-974E-22C046A43763}' ($common + @(@('InterfaceLuid', $T::Currency), @('L2ProfileId', $T::Long), @('ConnectedTime', $T::Long), @('ConnectStartTime', $T::Currency), @('L2ProfileFlags', $T::Long)))
Add-Row $conn @{ TimeStamp = $ts; AppId = 2; UserId = 4; InterfaceLuid = ([long]71 -shl 48); L2ProfileId = 5; ConnectedTime = 3600; ConnectStartTime = (& $ft '2026-09-20T09:00:00Z'); L2ProfileFlags = 0 }

$push = New-Table '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}' ($common + @(@('NotificationType', $T::Long), @('PayloadSize', $T::Long), @('NetworkType', $T::Long)))
Add-Row $push @{ TimeStamp = $ts; AppId = 3; UserId = 5; NotificationType = 2; PayloadSize = 512; NetworkType = 1 }

$lt = New-Table '{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT' ($common + @(
    @('ActiveAcTime', $T::Long), @('ActiveDcTime', $T::Long), @('ActiveDischargeTime', $T::Long), @('ActiveEnergy', $T::Long),
    @('CsAcTime', $T::Long), @('CsDcTime', $T::Long), @('CsDischargeTime', $T::Long), @('CsEnergy', $T::Long),
    @('CycleCount', $T::Long), @('DesignedCapacity', $T::Long), @('FullChargedCapacity', $T::Long), @('ConfigurationHash', $T::Currency)))
Add-Row $lt @{ TimeStamp = $ts; AppId = 1; UserId = 4; ActiveAcTime = 1; ActiveDcTime = 2; ActiveDischargeTime = 3; ActiveEnergy = 4; CsAcTime = 5; CsDcTime = 6; CsDischargeTime = 7; CsEnergy = 8; CycleCount = 9; DesignedCapacity = 50000; FullChargedCapacity = 45000; ConfigurationHash = [long]77 }

$energy = New-Table '{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}' ($common + @(
    @('EventTimestamp', $T::Currency), @('StateTransition', $T::Long), @('DesignedCapacity', $T::Long), @('FullChargedCapacity', $T::Long),
    @('ChargeLevel', $T::Long), @('CycleCount', $T::Long), @('ConfigurationHash', $T::Currency)))
Add-Row $energy @{ TimeStamp = $ts; AppId = 1; UserId = 4; EventTimestamp = (& $ft '2026-09-20T08:30:00Z'); StateTransition = 1; DesignedCapacity = 50000; FullChargedCapacity = 45000; ChargeLevel = 80; CycleCount = 9; ConfigurationHash = [long]77 }

$vfu = New-Table '{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}' ($common + @(@('Flags', $T::Long), @('StartTime', $T::Currency), @('EndTime', $T::Currency)))
Add-Row $vfu @{ TimeStamp = $ts; AppId = 1; UserId = 4; Flags = 6; StartTime = (& $ft '2026-09-20T09:59:58Z'); EndTime = ((& $ft '2026-09-20T09:59:58Z') + 15000000) }

$tl = New-Table '{5C8CF1C7-7257-4F13-B223-970EF5939312}' ($common + @(@('DurationMS', $T::Long), @('EndTime', $T::Currency)))
Add-Row $tl @{ TimeStamp = $ts; AppId = 3; UserId = 5; DurationMS = 60000; EndTime = (& $ft '2026-09-20T11:00:00Z') }

$Api::JetCloseDatabase($ses, $dbid, [Microsoft.Isam.Esent.Interop.CloseDatabaseGrbit]::None)
$Api::JetDetachDatabase($ses, $db)
$ses.Dispose()
$inst.Dispose()
Copy-Item $db (Join-Path $here 'SRUDB.dat') -Force
Remove-Item $work -Recurse -Force
'SRUDB.dat: {0} bytes' -f (Get-Item (Join-Path $here 'SRUDB.dat')).Length
