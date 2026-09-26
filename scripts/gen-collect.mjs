// Generates src/ui/kapeTargets.ts from KapeFiles' targets
// (https://github.com/EricZimmerman/KapeFiles, Targets/**/*.tkape, MIT): every
// artifact KAPE knows where to find, for the Collect panel.
//
//   node scripts/gen-collect.mjs path/to/KapeFiles/Targets path/to/SQLECmd/SQLMap/Maps
//
// A target's name is its file name, which is what `kape.exe --target` takes.
// Compound targets (Targets/Compound) only list other targets and become
// bundles; !Disabled is skipped as KAPE skips it. `reads` names the parsers here
// that read an entry's files, so the panel can say what is and is not covered.
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { basename, join, relative, sep } from 'node:path';
import { parse } from 'yaml';

const [root, mapsRoot] = process.argv.slice(2);
if (!root || !mapsRoot) throw new Error('usage: node scripts/gen-collect.mjs <KapeFiles/Targets> <SQLECmd/SQLMap/Maps>');

const walk = (dir, ext) =>
  readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(join(dir, e.name), ext) : e.name.toLowerCase().endsWith(ext) ? [join(dir, e.name)] : [],
  );

// SQLECmd identifies a database by a query, but each map names the file it was
// written for; a KAPE entry that asks for that file is one SQLECmd reads.
const sqlNames = walk(mapsRoot, '.smap')
  .map((f) => parse(readFileSync(f, 'utf8'), { schema: 'failsafe' })?.FileName)
  .filter((n) => typeof n === 'string' && !/^(BlobTest|CarsDB|random)/i.test(n))
  .map((n) => n.toLowerCase());

const HIVE =
  /^(ntuser\.dat|usrclass\.dat|system|system1|software|sam|security|default|components|drivers|elam|bbi|amcache\.hve|syscache\.hve|[^*]*\.hve|_registry_\*)(\*|\.log\d?|\.log\*)?$/;

/** Which parsers here read the files an entry collects. */
function reads(path, mask, recursive) {
  const m = (mask ?? '').toLowerCase();
  const p = path.toLowerCase();
  const any = m === '' || m === '*' || m === '*.*';
  const ext = (e) => m.endsWith(e) || m.endsWith(`${e}*`);
  const out = new Set();
  if (ext('.pf') || (any && p.endsWith('\\prefetch\\'))) out.add('prefetch');
  if (ext('.evtx') || (any && p.includes('\\winevt\\logs\\'))) out.add('evtx');
  if (ext('.lnk') || (any && /\\(recent|desktop|startup)\\$/.test(p))) out.add('lnk');
  // Recent\ taken whole holds the jump list folders too.
  if (
    ext('.automaticdestinations-ms') ||
    ext('.customdestinations-ms') ||
    (any && /(automatic|custom)destinations\\$/.test(p)) ||
    (any && recursive && /\\recent\\$/.test(p))
  )
    out.add('jumplist');
  if ((m.startsWith('$i') && /\$recycle\.bin|recycler/.test(p)) || m === 'info2') out.add('recyclebin');
  if (HIVE.test(m) || (any && /\\regback\\$/.test(p))) out.add('registry');
  if (/^(ntuser|usrclass)\.dat\*?$/.test(m)) out.add('shellbags');
  if (/^system\*?$/.test(m)) out.add('appcompatcache');
  if (/^amcache\.hve\*?$/.test(m)) out.add('amcache');
  if (m === '$mft') out.add('mft');
  if (m === '$j' || m === '$usnjrnl:$j') out.add('usnjrnl');
  if (m === '$boot') out.add('boot');
  if (m === '$secure:$sds' || m === '$secure_$sds') out.add('sds');
  if (m === '$i30') out.add('i30');
  if (m === 'recentfilecache.bcf') out.add('recentfilecache');
  if (/^activitiescache\.db\*?$/.test(m) || (any && p.includes('\\connecteddevicesplatform\\'))) out.add('wxtcmd');
  if (m === 'srudb.dat' || (any && p.endsWith('\\sru\\'))) out.add('srum');
  // Only a mask that names the file ("History", "History*"): "*.db" or "D*"
  // would claim databases no map was written for.
  if (m && sqlNames.includes(m.replace(/\*$/, ''))) out.add('sqlite');
  return [...out];
}

const str = (v) => (typeof v === 'string' ? v.trim() : '');
const targets = [];
const bundles = [];
const rejected = [];
for (const file of walk(root, '.tkape').sort((a, b) => a.localeCompare(b, 'en'))) {
  const rel = relative(root, file);
  const group = rel.split(sep)[0];
  if (group === '!Disabled') continue;
  let t;
  try {
    t = parse(readFileSync(file, 'utf8'), { schema: 'failsafe' });
  } catch (e) {
    rejected.push(`${rel}: ${e.message.split('\n')[0]}`);
    continue;
  }
  if (!t || !Array.isArray(t.Targets)) {
    rejected.push(`${rel}: no Targets`);
    continue;
  }
  const name = basename(file).replace(/\.tkape$/i, '');
  const includes = [];
  const entries = [];
  for (const e of t.Targets) {
    const path = str(e?.Path);
    if (!path) continue;
    if (/\.tkape$/i.test(path)) {
      includes.push(path.replace(/\.tkape$/i, ''));
      continue;
    }
    const mask = str(e.FileMask) || null;
    const recursive = /^true$/i.test(str(e.Recursive));
    entries.push({ name: str(e.Name), category: str(e.Category), path, mask, recursive, reads: reads(path, mask, recursive) });
  }
  const description = str(t.Description);
  if (group === 'Compound') bundles.push({ name, description, includes });
  else targets.push({ name, group, description, entries, includes, kape: true });
}

// KAPE finds a target by file name, so case does not matter ("Combofix" is
// listed as "ComboFix"); give each the name its file has.
const canonical = new Map([...targets, ...bundles].map((t) => [t.name.toLowerCase(), t.name]));
for (const t of [...targets, ...bundles]) t.includes = t.includes.map((n) => canonical.get(n.toLowerCase()) ?? n);

// What a parser here reads and KAPE has no target for.
targets.push({
  name: '$I30',
  group: 'Windows',
  description: "A directory's NTFS index (MFTECmd). KAPE has no target for it: export one with FTK Imager or a raw copy tool",
  entries: [{ name: '$I30', category: 'FileSystem', path: 'C:\\', mask: '$I30', recursive: false, reads: ['i30'] }],
  includes: [],
  kape: false,
});

// Windows first: what nearly every case needs.
const GROUPS = ['Windows', 'Browsers', 'Apps', 'Antivirus', 'Logs', 'P2P'];
targets.sort((a, b) => GROUPS.indexOf(a.group) - GROUPS.indexOf(b.group) || a.name.localeCompare(b.name, 'en'));

const out = `// Auto-generated by scripts/gen-collect.mjs from KapeFiles
// (https://github.com/EricZimmerman/KapeFiles). ${targets.length} targets, ${bundles.length} bundles. Do not edit by hand.
export interface KapeEntry {
  name: string;
  category: string;
  /** KAPE's path: from C:\\, with %user% for each profile and * as a wildcard. */
  path: string;
  mask: string | null;
  recursive: boolean;
  /** Parsers here that read these files. */
  reads: string[];
}
export interface KapeTarget {
  name: string;
  group: string;
  description: string;
  entries: KapeEntry[];
  /** Other targets this one pulls in. */
  includes: string[];
  /** False for an artifact KAPE has no target for. */
  kape: boolean;
}
export interface KapeBundle {
  name: string;
  description: string;
  includes: string[];
}
export const KAPE_TARGETS: KapeTarget[] = ${JSON.stringify(targets)};
export const KAPE_BUNDLES: KapeBundle[] = ${JSON.stringify(bundles)};
`;
writeFileSync(new URL('../src/ui/kapeTargets.ts', import.meta.url), out);

const covered = {};
for (const t of targets) for (const e of t.entries) for (const r of e.reads) covered[r] = (covered[r] ?? 0) + 1;
console.log(`${targets.length} targets, ${bundles.length} bundles, ${(out.length / 1024).toFixed(0)} KB`);
console.log('entries per parser:', covered);
for (const r of rejected) console.log(`skipped ${r}`);
