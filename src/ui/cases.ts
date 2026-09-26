/**
 * Cases: a customer or investigation, the artifacts collected for it, and a
 * copy of every one of those files kept in this browser until the analyst
 * removes it.
 *
 * Files live in the Origin Private File System, the browser's own on-disk
 * storage for this site: large, fast, not visible to other sites, and never
 * sent anywhere. Parsed rows are not stored - parsing is deterministic, so a
 * case re-reads its files when they are opened, and what is on screen is
 * always what the current parsers make of the original bytes.
 *
 *   cases/index.json                 the cases
 *   cases/<caseId>/artifacts.json    that case's artifacts
 *   cases/<caseId>/files/<id>        each artifact's bytes, byte for byte
 *   cases/<caseId>/timeline.json     the investigation timeline
 */
import { EMPTY_TIMELINE, isTimeline, type Timeline } from './timeline';

export interface CaseInfo {
  id: string;
  name: string;
  customer: string;
  reference: string;
  examiner: string;
  notes: string;
  created: string;
  updated: string;
}

export interface CaseArtifact {
  id: string;
  /** Where it was in what was added: a folder path for a KAPE collection. */
  path: string;
  size: number;
  lastModified: number;
  added: string;
  /** What it was recognised as when added. */
  detected: string | null;
  /** A parser the analyst chose with Read as, kept for next time. */
  parserId: string | null;
}

const isStr = (v: unknown): v is string => typeof v === 'string';

/** The file name at the end of a stored path, whichever separator it uses. */
export const baseName = (path: string) => path.split(/[\\/]/).pop() ?? path;
/** The folder part of a stored path, or '' for a bare name. */
export const dirName = (path: string) => path.slice(0, Math.max(0, path.length - baseName(path).length - 1));

export function isCaseList(v: unknown): v is CaseInfo[] {
  return (
    Array.isArray(v) &&
    v.every(
      (c) =>
        c &&
        typeof c === 'object' &&
        ['id', 'name', 'customer', 'reference', 'examiner', 'notes', 'created', 'updated'].every((k) =>
          isStr((c as Record<string, unknown>)[k]),
        ),
    )
  );
}

export function isArtifactList(v: unknown): v is CaseArtifact[] {
  return (
    Array.isArray(v) &&
    v.every(
      (a) =>
        a &&
        typeof a === 'object' &&
        isStr(a.id) &&
        isStr(a.path) &&
        Number.isFinite(a.size) &&
        Number.isFinite(a.lastModified) &&
        isStr(a.added) &&
        (a.detected === null || isStr(a.detected)) &&
        (a.parserId === null || isStr(a.parserId)),
    )
  );
}

/**
 * The transaction logs that belong to a file: a hive's "<hive>.LOG", ".LOG1"
 * or ".LOG2", and a SQLite database's "<db>-wal" write-ahead log. Paths are
 * compared case-insensitively, as Windows names them.
 */
export function logsFor<T extends { path: string }>(hive: T, all: T[]): T[] {
  const base = hive.path.toLowerCase();
  return all.filter((a) => {
    const p = a.path.toLowerCase();
    return a !== hive && p.startsWith(base) && /^(\.log[12]?|-wal)$/.test(p.slice(base.length));
  });
}

/** A transaction log whose hive or database is also present, and so is read with it rather than on its own. */
export function isPairedLog<T extends { path: string }>(a: T, all: T[]): boolean {
  const m = /^(.*)(\.log[12]?|-wal)$/i.exec(a.path);
  return !!m && all.some((b) => b.path.toLowerCase() === m[1].toLowerCase());
}

/**
 * The $MFT a USN journal takes its parent paths from, as MFTECmd's -m does:
 * the one at the root of the journal's volume (KAPE keeps "C/$Extend/$J"
 * beside "C/$MFT"), or failing that the only one there is.
 */
export function mftFor<T extends { path: string }>(journal: T, all: T[]): T | null {
  if (!/^\$j$|usnjrnl/i.test(baseName(journal.path))) return null;
  const mfts = all.filter((a) => baseName(a.path).toLowerCase() === '$mft');
  const root = dirName(journal.path).replace(/(^|[\\/])\$extend$/i, '');
  return mfts.find((m) => dirName(m.path) === root) ?? (mfts.length === 1 ? mfts[0] : null);
}

/**
 * The SOFTWARE hive a SRUDB.dat takes user and network names from, as
 * SrumECmd's -r does: the one in the same Windows\System32 (KAPE keeps
 * "C/Windows/System32/sru/SRUDB.dat" beside "C/Windows/System32/config/SOFTWARE"),
 * one in the same folder, or the only one there is.
 */
export function softwareFor<T extends { path: string }>(db: T, all: T[]): T | null {
  if (baseName(db.path).toLowerCase() !== 'srudb.dat') return null;
  const hives = all.filter((a) => baseName(a.path).toLowerCase() === 'software');
  const dir = dirName(db.path).toLowerCase();
  const config = dir.replace(/(^|[\\/])sru$/, '$1config');
  const inDir = (d: string) => hives.find((h) => dirName(h.path).toLowerCase() === d);
  return inDir(config) ?? inDir(dir) ?? (hives.length === 1 ? hives[0] : null);
}

/** Everything an artifact is read with: a hive's transaction logs, a journal's $MFT, SRUM's SOFTWARE hive. */
export function companionsFor<T extends { path: string }>(a: T, all: T[]): T[] {
  return [...logsFor(a, all), mftFor(a, all), softwareFor(a, all)].filter((x): x is T => x !== null);
}

/** OPFS needs a secure context and a browser that can write files from the page. */
export function casesSupported(): boolean {
  return (
    typeof navigator !== 'undefined' &&
    !!navigator.storage?.getDirectory &&
    typeof FileSystemFileHandle !== 'undefined' &&
    'createWritable' in FileSystemFileHandle.prototype
  );
}

async function casesDir(): Promise<FileSystemDirectoryHandle> {
  const root = await navigator.storage.getDirectory();
  return root.getDirectoryHandle('cases', { create: true });
}

async function readJson<T>(dir: FileSystemDirectoryHandle, name: string, valid: (v: unknown) => v is T, fallback: T): Promise<T> {
  try {
    const file = await (await dir.getFileHandle(name)).getFile();
    const parsed: unknown = JSON.parse(await file.text());
    return valid(parsed) ? parsed : fallback;
  } catch {
    return fallback;
  }
}

async function writeJson(dir: FileSystemDirectoryHandle, name: string, data: unknown): Promise<void> {
  // A writable writes to a swap file and replaces the original on close, so
  // a crash mid-write leaves the previous version, not half a file.
  const w = await (await dir.getFileHandle(name, { create: true })).createWritable();
  await w.write(JSON.stringify(data));
  await w.close();
}

export async function listCases(): Promise<CaseInfo[]> {
  return readJson(await casesDir(), 'index.json', isCaseList, []);
}

export async function saveCase(info: CaseInfo): Promise<CaseInfo[]> {
  const dir = await casesDir();
  const list = await readJson(dir, 'index.json', isCaseList, []);
  const next = [...list.filter((c) => c.id !== info.id), { ...info, updated: new Date().toISOString() }].sort((a, b) =>
    a.name.localeCompare(b.name),
  );
  await dir.getDirectoryHandle(info.id, { create: true });
  await writeJson(dir, 'index.json', next);
  // Ask the browser not to clear this site's storage under disk pressure.
  // It may say no; the case still works, it is just not guaranteed to stay.
  await navigator.storage.persist?.().catch(() => false);
  return next;
}

export function newCase(fields: Omit<CaseInfo, 'id' | 'created' | 'updated'>): CaseInfo {
  const now = new Date().toISOString();
  return { ...fields, id: crypto.randomUUID(), created: now, updated: now };
}

/** Deletes a case and every file stored for it. */
export async function deleteCase(id: string): Promise<CaseInfo[]> {
  const dir = await casesDir();
  const list = (await readJson(dir, 'index.json', isCaseList, [])).filter((c) => c.id !== id);
  await dir.removeEntry(id, { recursive: true }).catch(() => undefined);
  await writeJson(dir, 'index.json', list);
  return list;
}

/** The case's investigation timeline, kept beside its artifacts. */
export async function loadTimeline(caseId: string): Promise<Timeline> {
  const dir = await (await casesDir()).getDirectoryHandle(caseId, { create: true });
  return readJson(dir, 'timeline.json', isTimeline, EMPTY_TIMELINE);
}

export async function saveTimeline(caseId: string, t: Timeline): Promise<void> {
  const dir = await (await casesDir()).getDirectoryHandle(caseId, { create: true });
  await writeJson(dir, 'timeline.json', t);
}

export async function listArtifacts(caseId: string): Promise<CaseArtifact[]> {
  const dir = await (await casesDir()).getDirectoryHandle(caseId, { create: true });
  return readJson(dir, 'artifacts.json', isArtifactList, []);
}

async function saveArtifacts(caseId: string, list: CaseArtifact[]): Promise<void> {
  const dir = await (await casesDir()).getDirectoryHandle(caseId, { create: true });
  await writeJson(dir, 'artifacts.json', list);
}

export interface Incoming {
  file: File;
  /** Path relative to what was dropped or picked; the file name if none. */
  path: string;
}

/**
 * Copies files into a case. Each file is streamed to disk, so a multi-gigabyte
 * log never has to fit in memory. Stops at the first file that cannot be
 * stored (usually a full disk) and returns what was stored and why it stopped.
 *
 * Cancelling (the signal) stops the copy mid-file and removes everything this
 * call had copied, so the case is left as it was before.
 */
export async function addToCase(
  caseId: string,
  incoming: Incoming[],
  detect: (file: File) => Promise<string | null>,
  onProgress?: (done: number, total: number) => void,
  signal?: AbortSignal,
): Promise<{ added: CaseArtifact[]; all: CaseArtifact[]; error: string | null; cancelled: boolean }> {
  const caseDir = await (await casesDir()).getDirectoryHandle(caseId, { create: true });
  const files = await caseDir.getDirectoryHandle('files', { create: true });
  const before = await readJson(caseDir, 'artifacts.json', isArtifactList, []);
  const all = [...before];
  const added: CaseArtifact[] = [];
  const total = incoming.reduce((n, f) => n + f.file.size, 0);
  let done = 0;
  let error: string | null = null;
  // Progress moves within a file too, at most ten times a second.
  let reported = 0;
  const report = (n: number) => {
    const now = performance.now();
    if (now - reported > 100 || n === total) {
      reported = now;
      onProgress?.(n, total);
    }
  };

  for (const { file, path } of incoming) {
    if (signal?.aborted) break;
    const id = crypto.randomUUID();
    try {
      const w = await (await files.getFileHandle(id, { create: true })).createWritable();
      let copied = 0;
      const count = new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, c) {
          copied += chunk.byteLength;
          report(done + copied);
          c.enqueue(chunk);
        },
      });
      await file.stream().pipeThrough(count).pipeTo(w, { signal });
      const artifact: CaseArtifact = {
        id,
        path,
        size: file.size,
        lastModified: file.lastModified,
        added: new Date().toISOString(),
        detected: await detect(file),
        parserId: null,
      };
      all.push(artifact);
      added.push(artifact);
    } catch (e) {
      await files.removeEntry(id).catch(() => undefined);
      if (signal?.aborted) break;
      error = `${path} could not be stored: ${(e as Error).message}`;
      break;
    }
    done += file.size;
    onProgress?.(done, total);
    // Keep the list on disk current, so an interrupted import keeps what it copied.
    if (added.length % 50 === 0) await saveArtifacts(caseId, all);
  }
  if (signal?.aborted) {
    for (const a of added) await files.removeEntry(a.id).catch(() => undefined);
    await saveArtifacts(caseId, before);
    return { added: [], all: before, error: null, cancelled: true };
  }
  await saveArtifacts(caseId, all);
  return { added, all, error, cancelled: false };
}

/** The stored copy of an artifact, as a File the parsers can read. */
export async function artifactFile(caseId: string, artifact: CaseArtifact): Promise<File> {
  const files = await (await (await casesDir()).getDirectoryHandle(caseId)).getDirectoryHandle('files');
  const stored = await (await files.getFileHandle(artifact.id)).getFile();
  // Give it back its own name, so detection by name and the file list read as they did.
  return new File([stored], baseName(artifact.path), {
    lastModified: artifact.lastModified,
  });
}

export async function removeArtifacts(caseId: string, ids: string[]): Promise<CaseArtifact[]> {
  const caseDir = await (await casesDir()).getDirectoryHandle(caseId);
  const files = await caseDir.getDirectoryHandle('files', { create: true });
  for (const id of ids) await files.removeEntry(id).catch(() => undefined);
  const next = (await readJson(caseDir, 'artifacts.json', isArtifactList, [])).filter((a) => !ids.includes(a.id));
  await saveArtifacts(caseId, next);
  return next;
}

export async function setArtifactParser(caseId: string, id: string, parserId: string | null): Promise<CaseArtifact[]> {
  const next = (await listArtifacts(caseId)).map((a) => (a.id === id ? { ...a, parserId } : a));
  await saveArtifacts(caseId, next);
  return next;
}

export async function storageUse(): Promise<{ used: number; quota: number; persisted: boolean }> {
  const est = await navigator.storage.estimate();
  const persisted = (await navigator.storage.persisted?.()) ?? false;
  return { used: est.usage ?? 0, quota: est.quota ?? 0, persisted };
}

/**
 * Every file in a drop, including the contents of dropped folders, with its
 * path inside what was dropped. A KAPE collection holds many files with the
 * same name (an NTUSER.DAT per user), and the path is what tells them apart.
 */
export async function droppedFiles(items: DataTransferItemList): Promise<Incoming[]> {
  // Both must be taken now: the list is emptied once the drop event returns.
  const taken = [...items]
    .filter((i) => i.kind === 'file')
    .map((i) => ({ entry: i.webkitGetAsEntry(), file: i.getAsFile() }));
  const entries = taken.map((t) => t.entry).filter((e): e is FileSystemEntry => e !== null);
  const out: Incoming[] = taken
    .filter((t) => t.entry === null && t.file !== null)
    .map((t) => ({ file: t.file as File, path: (t.file as File).name }));

  const walk = async (entry: FileSystemEntry, prefix: string): Promise<void> => {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isFile) {
      const file = await new Promise<File>((res, rej) => (entry as FileSystemFileEntry).file(res, rej));
      out.push({ file, path });
      return;
    }
    const reader = (entry as FileSystemDirectoryEntry).createReader();
    // readEntries hands back at most 100 entries per call.
    for (;;) {
      const batch = await new Promise<FileSystemEntry[]>((res, rej) => reader.readEntries(res, rej));
      if (batch.length === 0) break;
      for (const child of batch) await walk(child, path);
    }
  };

  for (const e of entries) await walk(e, '');
  return out;
}

/** Files from an <input>, keeping folder paths when a folder was picked. */
export function pickedFiles(list: FileList): Incoming[] {
  return [...list].map((file) => ({ file, path: file.webkitRelativePath || file.name }));
}
