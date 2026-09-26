// The Collect panel's logic: where each KAPE target's files live, what to paste
// into the file dialog to get there, where a picked file goes in the case, and
// the KAPE command line for what cannot be picked while Windows runs.
import type { KapeBundle, KapeEntry, KapeTarget } from './kapeTargets';

export interface Where {
  /** Blank for this computer, or the root of a mounted image or KAPE output ("E:\"). */
  source: string;
  /** The profile folder under Users; blank for whoever is signed in here. */
  user: string;
}

/** The entry's folder up to its first wildcard: the deepest one a dialog can open. */
function fixedFolder(path: string): string[] {
  const parts = path.split('\\').filter(Boolean);
  const i = parts.findIndex((p) => p.includes('*'));
  return i < 0 ? parts : parts.slice(0, i);
}

/**
 * The folder to paste into the file dialog. On this computer an unnamed user
 * is %USERPROFILE%, which the Windows dialog expands itself; elsewhere the path
 * stops at the Users folder so the profile can be chosen there.
 */
export function dialogPath(e: KapeEntry, w: Where): string {
  let parts = fixedFolder(e.path);
  const u = parts.findIndex((p) => /%users?%/i.test(p));
  if (u >= 0) {
    if (w.user.trim()) parts = parts.map((p, i) => (i === u ? w.user.trim() : p));
    else if (!w.source.trim() && u === 2 && /^users$/i.test(parts[1])) parts = ['%USERPROFILE%', ...parts.slice(3)];
    else parts = parts.slice(0, u);
  }
  if (w.source.trim() && /^[a-z]:$/i.test(parts[0])) parts = [w.source.trim().replace(/[\\/]+$/, ''), ...parts.slice(1)];
  return `${parts.join('\\')}\\`;
}

/**
 * Where a picked file is kept in the case: under the folder the artifact lives
 * in on the evidence drive, so the navigator shows it where Windows had it.
 * `relative` is a folder pick's webkitRelativePath, or a lone file's name.
 */
export function casePath(e: KapeEntry, w: Where, relative: string): string {
  const parts = fixedFolder(e.path).map((p, i) => (i === 0 && /^[a-z]:$/i.test(p) ? p[0].toUpperCase() : p.replace(/%users?%/i, w.user.trim() || 'user')));
  const rel = relative.split('/').filter(Boolean);
  // A folder picked at the artifact's own location would otherwise repeat its name.
  if (rel.length > 1 && rel[0].toLowerCase() === parts[parts.length - 1]?.toLowerCase()) rel.shift();
  return [...parts, ...rel].join('/');
}

/** Why picking this entry from a running Windows may not work, if it may not. */
export function caveat(e: KapeEntry): string | null {
  const p = e.path.toLowerCase();
  if (e.mask?.startsWith('$') && (p === 'c:\\' || p.startsWith('c:\\$extend'))) {
    return 'NTFS metadata: Windows hides it from every file dialog. Collect it with KAPE or FTK Imager, then pick the copy.';
  }
  if (e.reads.some((r) => ['registry', 'evtx', 'srum', 'amcache'].includes(r))) {
    return 'In use while Windows runs and needs administrator. Collect it with KAPE (it reads the disk raw) or pick it from a mounted image.';
  }
  if (/^c:\\(windows|windows\.old|programdata|\$recycle\.bin|system volume information)\\/.test(p)) return 'May need administrator.';
  return null;
}

/** Every target a bundle pulls in, following bundles that include bundles. */
export function expandBundle(name: string, bundles: KapeBundle[], seen = new Set<string>()): string[] {
  if (seen.has(name)) return [];
  seen.add(name);
  const b = bundles.find((x) => x.name === name);
  if (!b) return [name];
  return b.includes.flatMap((n) => expandBundle(n, bundles, seen));
}

/** The KAPE command line that collects the chosen targets from the source drive. */
export function kapeCommand(names: string[], source: string, dest: string): string {
  const q = (s: string) => (/[\s&^|<>]/.test(s) ? `"${s}"` : s);
  const src = source.trim().replace(/[\\/]+$/, '') || 'C:';
  return `kape.exe --tsource ${q(src)} --tdest ${q(dest.trim() || 'X:\\KAPE')} --target ${q(names.join(','))}`;
}

/** Targets matching every word of the query, in name, description, path or file mask. */
export function findTargets(targets: KapeTarget[], query: string, group: string, readHereOnly: boolean): KapeTarget[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  return targets.filter((t) => {
    if (group && t.group !== group) return false;
    if (readHereOnly && !t.entries.some((e) => e.reads.length)) return false;
    if (!words.length) return true;
    const text = [t.name, t.description, ...t.entries.flatMap((e) => [e.name, e.category, e.path, e.mask ?? ''])].join(' ').toLowerCase();
    return words.every((w) => text.includes(w));
  });
}
