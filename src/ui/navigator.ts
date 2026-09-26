/**
 * Finding your way around a case: what each artifact is, a filter over names,
 * folders, extensions, kinds and sizes, the folder tree a KAPE collection
 * arrives as, and the fuzzy match behind the quick switcher.
 */

export interface Entry {
  /** Stable key: the stored artifact's id, or the session result's id. */
  key: string;
  path: string;
  name: string;
  dir: string;
  /** Lower-case, with its dot; '' when there is none. */
  ext: string;
  size: number;
  /** Parser id it reads as, or null when nothing recognises it. */
  kind: string | null;
  /** The kind's display name, e.g. "Prefetch". */
  kindName: string;
  /** Read into memory in this session. */
  opened: boolean;
}

export interface Category {
  id: string;
  label: string;
}

/** Artifacts grouped the way an examiner thinks about them. */
export const CATEGORIES: Array<Category & { parsers: string[] }> = [
  { id: 'events', label: 'Event logs', parsers: ['evtx'] },
  { id: 'registry', label: 'Registry', parsers: ['registry', 'shellbags', 'appcompatcache'] },
  { id: 'execution', label: 'Program execution', parsers: ['prefetch', 'amcache', 'recentfilecache', 'srum'] },
  { id: 'filesystem', label: 'File system (NTFS)', parsers: ['mft', 'usnjrnl', 'boot', 'sds', 'i30'] },
  { id: 'links', label: 'Shortcuts & jump lists', parsers: ['lnk', 'jumplist'] },
  { id: 'recycle', label: 'Recycle Bin', parsers: ['recyclebin'] },
  { id: 'databases', label: 'Databases & browsers', parsers: ['sqlite', 'wxtcmd'] },
];
export const OTHER: Category = { id: 'other', label: 'Other' };
export const UNRECOGNISED: Category = { id: 'unrecognised', label: 'Unrecognised' };

export function categoryOf(kind: string | null): Category {
  if (!kind) return UNRECOGNISED;
  return CATEGORIES.find((c) => c.parsers.includes(kind)) ?? OTHER;
}

export const baseName = (path: string) => path.split(/[\\/]/).pop() ?? path;
export const dirOf = (path: string) => path.slice(0, Math.max(0, path.length - baseName(path).length - 1));
export const extOf = (name: string) => {
  const i = name.lastIndexOf('.');
  return i > 0 ? name.slice(i).toLowerCase() : '';
};

const UNITS: Record<string, number> = { b: 1, kb: 1024, mb: 1024 ** 2, gb: 1024 ** 3 };

type Test = (e: Entry) => boolean;

/**
 * The navigator's filter. Words are ANDed, and each may be:
 *   evtx          anywhere in the path
 *   ext:pf *.pf .pf   the extension
 *   in:Prefetch   a folder in the path
 *   type:registry a kind or category ("type:event", "type:unrecognised")
 *   size>10mb size<1kb
 *   -word         anything above, negated
 *   "two words"   a phrase
 */
export function entryFilter(query: string): Test {
  const tests: Test[] = [];
  for (const m of query.matchAll(/(-?)(?:"([^"]*)"|(\S+))/g)) {
    const negate = m[1] === '-';
    const word = (m[2] ?? m[3] ?? '').toLowerCase();
    if (!word) continue;
    let t: Test;
    const kv = /^(ext|in|dir|folder|type|kind):(.*)$/.exec(word);
    const size = /^size([<>]=?)(\d+(?:\.\d+)?)(b|kb|mb|gb)?$/.exec(word);
    if (kv) {
      const v = kv[2];
      if (kv[1] === 'ext') {
        const ext = v.startsWith('.') ? v : `.${v}`;
        t = (e) => e.ext === ext;
      } else if (kv[1] === 'type' || kv[1] === 'kind') {
        t = (e) => {
          const c = categoryOf(e.kind);
          return [e.kind ?? '', e.kindName, c.id, c.label].some((s) => s.toLowerCase().includes(v));
        };
      } else {
        t = (e) => e.dir.toLowerCase().split(/[\\/]/).some((d) => d.includes(v));
      }
    } else if (/^\*?\.[a-z0-9_-]+$/.test(word)) {
      const ext = word.replace(/^\*/, '');
      t = (e) => e.ext === ext;
    } else if (size) {
      const n = Number(size[2]) * UNITS[size[3] ?? 'b'];
      const op = size[1];
      t = (e) => (op === '>' ? e.size > n : op === '>=' ? e.size >= n : op === '<' ? e.size < n : e.size <= n);
    } else {
      t = (e) => e.path.toLowerCase().includes(word);
    }
    tests.push(negate ? (e) => !t(e) : t);
  }
  return (e) => tests.every((t) => t(e));
}

export type SortKey = 'path' | 'name' | 'size' | 'type';

export function sortEntries(entries: Entry[], key: SortKey): Entry[] {
  const by: Record<SortKey, (a: Entry, b: Entry) => number> = {
    path: (a, b) => a.path.localeCompare(b.path),
    name: (a, b) => a.name.localeCompare(b.name) || a.path.localeCompare(b.path),
    size: (a, b) => b.size - a.size || a.path.localeCompare(b.path),
    type: (a, b) => a.kindName.localeCompare(b.kindName) || a.path.localeCompare(b.path),
  };
  return [...entries].sort(by[key]);
}

export interface TreeNode {
  name: string;
  /** Folder path from the root, "/"-separated. */
  path: string;
  folders: TreeNode[];
  entries: Entry[];
  /** Entries in this folder and everything under it. */
  count: number;
}

/**
 * The folder tree of a set of entries. Folders that hold nothing but one other
 * folder are joined into one line ("C/Windows/System32"), as file managers do,
 * so a KAPE collection does not open five levels deep.
 */
export function buildTree(entries: Entry[]): TreeNode {
  const root: TreeNode = { name: '', path: '', folders: [], entries: [], count: 0 };
  for (const e of entries) {
    let node = root;
    node.count++;
    for (const part of e.dir.split(/[\\/]/).filter(Boolean)) {
      const path = node.path ? `${node.path}/${part}` : part;
      let next = node.folders.find((f) => f.name === part && f.path === path);
      if (!next) {
        next = { name: part, path, folders: [], entries: [], count: 0 };
        node.folders.push(next);
      }
      next.count++;
      node = next;
    }
    node.entries.push(e);
  }
  const compact = (n: TreeNode): TreeNode => {
    n.folders = n.folders.map(compact).sort((a, b) => a.name.localeCompare(b.name));
    if (n !== root && n.entries.length === 0 && n.folders.length === 1) {
      const only = n.folders[0];
      return { ...only, name: `${n.name}/${only.name}` };
    }
    return n;
  };
  return compact(root);
}

/** Every folder path in a tree, for expand-all. */
export function folderPaths(n: TreeNode, out: string[] = []): string[] {
  for (const f of n.folders) {
    out.push(f.path);
    folderPaths(f, out);
  }
  return out;
}

/**
 * The quick switcher's match: every character of the query, in order, in the
 * path. Higher is better: consecutive characters, matches at word starts and in
 * the file name count most; null when it does not match at all.
 */
export function fuzzyScore(query: string, path: string): number | null {
  const q = query.toLowerCase().replace(/\s+/g, '');
  if (!q) return 0;
  const p = path.toLowerCase();
  const nameStart = p.length - baseName(p).length;
  let score = 0;
  let at = -1;
  let run = 0;
  for (const ch of q) {
    const i = p.indexOf(ch, at + 1);
    if (i < 0) return null;
    run = i === at + 1 ? run + 1 : 0;
    score += 1 + run * 2;
    if (i === 0 || /[\\/._\-\s]/.test(p[i - 1])) score += 3;
    if (i >= nameStart) score += 2;
    at = i;
  }
  // Shorter paths win ties: "prefetch" should find the folder before a deep file mentioning it.
  return score - p.length / 100;
}
