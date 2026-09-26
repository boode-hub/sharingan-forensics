import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Logo } from './ui/Logo';
import { CasePanel } from './ui/CasePanel';
import { ArtifactPanel } from './ui/ArtifactPanel';
import { Viewer } from './ui/Viewer';
import { AddEventDialog, TimelineView, type Pending } from './ui/TimelineView';
import { Collect } from './ui/CollectView';
import { EMPTY_TIMELINE, type Timeline, type TimelineEvent } from './ui/timeline';
import {
  addToCase,
  artifactFile,
  casesSupported,
  companionsFor,
  deleteCase,
  droppedFiles,
  isPairedLog,
  listArtifacts,
  listCases,
  loadTimeline,
  logsFor,
  pickedFiles,
  removeArtifacts,
  saveCase,
  saveTimeline,
  setArtifactParser,
  storageUse,
  type CaseArtifact,
  type CaseInfo,
  type Incoming,
} from './ui/cases';
import { bytes, ZoneContext } from './ui/format';
import { unpackTicks } from './ui/fields';
import { baseName, dirOf, extOf, type Entry } from './ui/navigator';
import {
  DEFAULT_DETAIL_SIZES,
  isColour,
  isFlag,
  isPosition,
  isSavedList,
  isSizes,
  read,
  write,
  type DetailPosition,
  type DetailSizes,
  type SavedFilter,
} from './ui/storage';
import type { Column, Row } from './core/types';
import type { ParserInfo, WorkRequest, WorkResult, WorkerReady } from './worker';

let nextId = 1;

// Where times are shown. Evidence is read and kept in UTC whatever is chosen.
const HERE_ZONE = Intl.DateTimeFormat().resolvedOptions().timeZone;
const ZONES = Intl.supportedValuesOf('timeZone').filter((z) => z !== 'UTC' && z !== HERE_ZONE);
const isZone = (v: unknown): v is string => {
  if (typeof v !== 'string') return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: v });
    return true;
  } catch {
    return false;
  }
};
let nextPane = 1;

/** The accent the Phishing Email Analyzer ships with. */
const DEFAULT_ACCENT = '#9fef00';

/** One side of the main area and the parse result it shows. */
interface Pane {
  pid: number;
  id: number | null;
}

const isRatio = (v: unknown): v is number => typeof v === 'number' && v >= 0.15 && v <= 0.85;

export default function App() {
  const [results, setResults] = useState<WorkResult[]>([]);
  const [busy, setBusy] = useState(0);
  const [bigFiles, setBigFiles] = useState<string[]>([]);
  const [dragging, setDragging] = useState(false);
  const [known, setKnown] = useState<ParserInfo[]>([]);

  // The main area: one pane, or two side by side, and which of them the next
  // artifact opens in.
  const [panes, setPanes] = useState<Pane[]>([{ pid: 0, id: null }]);
  const [activePane, setActivePane] = useState(0);
  const [split, setSplit] = useState(() => read('splitRatio', 0.5, isRatio));
  const panesRef = useRef(panes);
  const activeRef = useRef(activePane);
  useEffect(() => {
    panesRef.current = panes;
    activeRef.current = activePane;
  }, [panes, activePane]);
  const mainArea = useRef<HTMLElement>(null);

  // Cases. With none chosen, files are read for this session only.
  const supported = useMemo(() => casesSupported(), []);
  const [cases, setCases] = useState<CaseInfo[]>([]);
  const [caseId, setCaseId] = useState<string | null>(() =>
    read('activeCase', null, (v): v is string | null => v === null || typeof v === 'string'),
  );
  const [artifacts, setArtifacts] = useState<CaseArtifact[]>([]);
  /** Which parse result belongs to which stored artifact. */
  const [artifactResult, setArtifactResult] = useState<Record<string, number>>({});
  const [importing, setImporting] = useState<{ done: number; total: number } | null>(null);
  const [caseError, setCaseError] = useState<string | null>(null);
  const [importNote, setImportNote] = useState<string | null>(null);
  const importAbort = useRef<AbortController | null>(null);
  const [storage, setStorage] = useState<{ used: number; quota: number; persisted: boolean } | null>(null);
  const pendingDetect = useRef(new Map<number, (parserId: string | null) => void>());

  const [position, setPosition] = useState<DetailPosition>(() => read('detailPosition', 'bottom', isPosition));
  const [accent, setAccent] = useState(() => read('accent', DEFAULT_ACCENT, isColour));
  const [sizes, setSizes] = useState<DetailSizes>(() => read('detailSizes', DEFAULT_DETAIL_SIZES, isSizes));
  const [builderOpen, setBuilderOpen] = useState(() => read('builderOpen', true, isFlag));
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [zone, setZone] = useState(() => read('timeZone', 'UTC', isZone));
  const [saved, setSaved] = useState<SavedFilter[]>(() => read('savedFilters', [], isSavedList));

  // The investigation timeline: kept with the case, or for this session only.
  const [view, setView] = useState<'artifacts' | 'timeline' | 'collect'>('artifacts');
  const [timeline, setTimelineState] = useState<Timeline>(EMPTY_TIMELINE);
  const [pending, setPending] = useState<Pending | null>(null);
  const [lastLane, setLastLane] = useState<string | null>(null);
  /** A row to bring into view in whichever pane shows its artifact. */
  const [focus, setFocus] = useState<{ key: string; index: number; nonce: number } | null>(null);

  // The file behind each result, so it can be read again as something else.
  // Some artifacts are a structure inside another: shell bags live in a
  // registry hive, and which of the two you want is a question only the
  // analyst can answer.
  const opened = useRef(new Map<number, { file: File; siblings?: File[]; artifactId?: string }>());
  const worker = useRef<Worker>(null);

  /** Shows a result in the active pane, or beside it (splitting the main area if it is not yet split). */
  const show = useCallback((id: number, beside: boolean) => {
    const ps = panesRef.current;
    let target = Math.min(activeRef.current, ps.length - 1);
    let next = ps;
    if (beside) {
      if (ps.length === 1) {
        next = [...ps, { pid: nextPane++, id: null }];
        target = 1;
      } else target = target === 0 ? 1 : 0;
    }
    next = next.map((p, i) => (i === target ? { ...p, id } : p));
    panesRef.current = next;
    activeRef.current = target;
    setPanes(next);
    setActivePane(target);
  }, []);

  useEffect(() => {
    const w = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' });
    w.onmessage = (e: MessageEvent<WorkResult | WorkerReady>) => {
      if ('ready' in e.data) {
        setKnown(e.data.parsers);
        return;
      }
      const result = e.data;
      if (result.detected) {
        pendingDetect.current.get(result.id)?.(result.parser?.id ?? null);
        pendingDetect.current.delete(result.id);
        return;
      }
      setBusy((n) => n - 1);
      // A result for something no longer open (the analyst switched cases
      // while it was being read) is dropped rather than shown in the wrong case.
      if (!opened.current.has(result.id)) return;
      if (result.rows) unpackTicks(result.rows);
      setResults((rs) => [...rs, result]);
      // The first file of a session fills an empty pane on its own.
      const ps = panesRef.current;
      const a = Math.min(activeRef.current, ps.length - 1);
      if (ps[a].id === null) show(result.id, false);
    };
    worker.current = w;
    return () => w.terminate();
  }, [show]);

  useEffect(() => {
    document.documentElement.style.setProperty('--accent', accent);
    write('accent', accent);
  }, [accent]);
  useEffect(() => {
    write('detailPosition', position);
  }, [position]);
  useEffect(() => {
    write('timeZone', zone);
  }, [zone]);
  useEffect(() => {
    write('detailSizes', sizes);
  }, [sizes]);
  useEffect(() => {
    write('builderOpen', builderOpen);
  }, [builderOpen]);
  useEffect(() => {
    write('splitRatio', split);
  }, [split]);

  const onSaved = useCallback((next: SavedFilter[]) => {
    setSaved(next);
    write('savedFilters', next);
  }, []);

  const ingest = useCallback((all: Incoming[]) => {
    for (const item of all) {
      const { file } = item;
      // A registry transaction log is not an artifact in its own right; it is
      // part of the hive beside it. Opening one on its own says nothing, so it
      // is handed to that hive instead of being parsed separately.
      if (isPairedLog(item, all)) continue;
      setBusy((n) => n + 1);
      // Everything in the file is parsed regardless of size — nothing is
      // truncated. But past this point it takes long enough that silence looks
      // like a hang, so say so rather than leave the analyst guessing.
      if (file.size >= 64 * 1024 * 1024) {
        setBigFiles((b) => [...b, `${file.name} (${bytes(file.size)})`]);
      }
      const siblings = companionsFor(item, all).map((c) => c.file);
      const id = nextId++;
      opened.current.set(id, { file, siblings: siblings.length > 0 ? siblings : undefined });
      worker.current?.postMessage({ id, file, siblings: siblings.length > 0 ? siblings : undefined } satisfies WorkRequest);
    }
  }, []);

  /** What a file is, asked of the worker without parsing it. */
  const detectFile = useCallback(
    (file: File) =>
      new Promise<string | null>((resolve) => {
        const id = nextId++;
        pendingDetect.current.set(id, resolve);
        worker.current?.postMessage({ id, file, detectOnly: true } satisfies WorkRequest);
      }),
    [],
  );

  const refreshStorage = useCallback(() => {
    if (supported) storageUse().then(setStorage).catch(() => undefined);
  }, [supported]);

  useEffect(() => {
    if (!supported) return;
    listCases()
      .then((list) => {
        setCases(list);
        // A remembered case that has since been deleted is not reopened.
        setCaseId((id) => (id && list.some((c) => c.id === id) ? id : null));
      })
      .catch(() => undefined);
    refreshStorage();
  }, [supported, refreshStorage]);

  // The chosen case's artifacts and timeline, read from storage whenever the case changes.
  useEffect(() => {
    write('activeCase', caseId);
    if (!caseId || !supported) return;
    let live = true;
    listArtifacts(caseId)
      .then((list) => live && setArtifacts(list))
      .catch(() => live && setArtifacts([]));
    loadTimeline(caseId)
      .then((t) => live && setTimelineState(t))
      .catch(() => live && setTimelineState(EMPTY_TIMELINE));
    return () => {
      live = false;
    };
  }, [caseId, supported]);

  /** Switching case starts from a clean page: what was open belonged to the other case. */
  const switchCase = useCallback((id: string | null) => {
    opened.current.clear();
    setResults([]);
    const one = [{ pid: nextPane++, id: null }];
    panesRef.current = one;
    activeRef.current = 0;
    setPanes(one);
    setActivePane(0);
    setArtifactResult({});
    setArtifacts([]);
    setTimelineState(EMPTY_TIMELINE);
    setFocus(null);
    setCaseError(null);
    setCaseId(id);
  }, []);

  const setTimeline = useCallback(
    (t: Timeline) => {
      setTimelineState(t);
      if (caseId) saveTimeline(caseId, t).catch((e: Error) => setCaseError(`The timeline could not be saved: ${e.message}`));
    },
    [caseId],
  );

  /** Reads a stored artifact, with its transaction logs when it is a hive, into a pane. */
  const openArtifact = useCallback(
    async (a: CaseArtifact, list: CaseArtifact[], beside = false) => {
      if (!caseId) return;
      const existing = artifactResult[a.id];
      if (existing !== undefined) {
        show(existing, beside);
        return;
      }
      try {
        const file = await artifactFile(caseId, a);
        const logs = await Promise.all(companionsFor(a, list).map((l) => artifactFile(caseId, l)));
        const id = nextId++;
        opened.current.set(id, { file, siblings: logs.length ? logs : undefined, artifactId: a.id });
        setArtifactResult((m) => ({ ...m, [a.id]: id }));
        setBusy((n) => n + 1);
        show(id, beside);
        worker.current?.postMessage({
          id,
          file,
          siblings: logs.length ? logs : undefined,
          parserId: a.parserId ?? undefined,
        } satisfies WorkRequest);
      } catch (e) {
        setCaseError(`${a.path} could not be read from this browser's storage: ${(e as Error).message}`);
      }
    },
    [caseId, artifactResult, show],
  );

  /** Files dropped or picked: kept in the case if one is open, else read for this session. */
  const addIncoming = useCallback(
    async (incoming: Incoming[]) => {
      if (incoming.length === 0) return;
      if (!caseId) {
        ingest(incoming);
        return;
      }
      setCaseError(null);
      setImportNote(null);
      setImporting({ done: 0, total: incoming.reduce((n, i) => n + i.file.size, 0) });
      const abort = new AbortController();
      importAbort.current = abort;
      const { added, all, error, cancelled } = await addToCase(
        caseId,
        incoming,
        detectFile,
        (done, total) => setImporting({ done, total }),
        abort.signal,
      ).catch((e: Error) => ({ added: [], all: artifacts, error: e.message, cancelled: false }));
      importAbort.current = null;
      setImporting(null);
      setArtifacts(all);
      if (error) setCaseError(error);
      if (cancelled) setImportNote('Upload cancelled. Nothing from it was kept in the case.');
      refreshStorage();
      // Open the first recognised one; a whole collection is opened one
      // artifact at a time, as the analyst picks them.
      const first = added.find((a) => a.detected && !isPairedLog(a, all));
      if (first) openArtifact(first, all);
    },
    [caseId, ingest, detectFile, artifacts, refreshStorage, openArtifact],
  );

  const removeArtifact = useCallback(
    async (a: CaseArtifact) => {
      if (!caseId) return;
      const logs = logsFor(a, artifacts);
      const what = logs.length ? `${a.path} and its ${logs.length} transaction log${logs.length > 1 ? 's' : ''}` : a.path;
      if (!window.confirm(`Remove ${what} from this case? The copy stored in this browser is deleted.`)) return;
      const next = await removeArtifacts(caseId, [a.id, ...logs.map((l) => l.id)]);
      setArtifacts(next);
      const rid = artifactResult[a.id];
      if (rid !== undefined) {
        opened.current.delete(rid);
        setResults((rs) => rs.filter((r) => r.id !== rid));
        setPanes((ps) => ps.map((p) => (p.id === rid ? { ...p, id: null } : p)));
        setArtifactResult((m) => {
          const n = { ...m };
          delete n[a.id];
          return n;
        });
      }
      refreshStorage();
    },
    [caseId, artifacts, artifactResult, refreshStorage],
  );

  const saveCaseInfo = useCallback(
    async (info: CaseInfo) => {
      try {
        setCases(await saveCase(info));
        if (info.id !== caseId) switchCase(info.id);
        refreshStorage();
      } catch (e) {
        setCaseError(`The case could not be saved: ${(e as Error).message}`);
      }
    },
    [caseId, switchCase, refreshStorage],
  );

  const removeCase = useCallback(
    async (info: CaseInfo) => {
      const n = info.id === caseId ? artifacts.length : null;
      const files = n === null ? 'every file stored for it' : `the ${n} file${n === 1 ? '' : 's'} stored for it`;
      if (!window.confirm(`Delete the case "${info.name}" and ${files}? This cannot be undone.`)) return;
      setCases(await deleteCase(info.id));
      if (info.id === caseId) switchCase(null);
      refreshStorage();
    },
    [caseId, artifacts, switchCase, refreshStorage],
  );

  /** Reads an artifact again with a parser the analyst picked. */
  const reparse = useCallback(
    (id: number, pid: string) => {
      const source = opened.current.get(id);
      if (!source) return;
      setBusy((n) => n + 1);
      // Replaces the result in place: the same file read two ways is one
      // artifact with a different question asked of it, not two artifacts.
      setResults((rs) => rs.filter((r) => r.id !== id));
      worker.current?.postMessage({ id, file: source.file, siblings: source.siblings, parserId: pid } satisfies WorkRequest);
      // In a case the choice is kept, so the artifact opens the same way next time.
      if (caseId && source.artifactId) {
        setArtifactParser(caseId, source.artifactId, pid).then(setArtifacts).catch(() => undefined);
      }
    },
    [caseId],
  );

  const activeCase = cases.find((c) => c.id === caseId) ?? null;
  const knownById = useMemo(() => new Map(known.map((p) => [p.id, p])), [known]);
  const resultById = useMemo(() => new Map(results.map((r) => [r.id, r])), [results]);
  // A hive's transaction logs are read with it, not listed on their own.
  const listedArtifacts = useMemo(() => artifacts.filter((a) => !isPairedLog(a, artifacts)), [artifacts]);

  // What the navigator lists: the case's artifacts, or the files of this session.
  const entries = useMemo<Entry[]>(() => {
    if (caseId) {
      return listedArtifacts.map((a) => {
        const name = baseName(a.path);
        const rid = artifactResult[a.id];
        const r = rid === undefined ? undefined : resultById.get(rid);
        const kind = r?.parser?.id ?? a.parserId ?? a.detected;
        return {
          key: a.id,
          path: a.path,
          name,
          dir: dirOf(a.path),
          ext: extOf(name),
          size: a.size,
          kind: r?.error ? null : kind,
          kindName: (kind && knownById.get(kind)?.name) || '',
          opened: rid !== undefined,
        };
      });
    }
    return results.map((r) => ({
      key: `r${r.id}`,
      path: r.fileName,
      name: r.fileName,
      dir: '',
      ext: extOf(r.fileName),
      size: r.fileSize,
      kind: r.parser?.id ?? null,
      kindName: r.parser?.name ?? '',
      opened: true,
    }));
  }, [caseId, listedArtifacts, artifactResult, resultById, results, knownById]);

  const resultOf = useCallback(
    (key: string): number | undefined => (caseId ? artifactResult[key] : Number(key.slice(1))),
    [caseId, artifactResult],
  );
  const panesOf = (key: string) => {
    const rid = resultOf(key);
    if (rid === undefined) return '';
    if (panes.length === 1) return panes[0].id === rid ? '•' : '';
    return (panes[0].id === rid ? 'L' : '') + (panes[1].id === rid ? 'R' : '');
  };
  const activeId = panes[Math.min(activePane, panes.length - 1)].id;
  const activeKey = activeId === null ? null : (entries.find((e) => resultOf(e.key) === activeId)?.key ?? null);

  /** The navigator key of a parse result: its case artifact's id, or "r<id>" in a session. */
  const keyOfResult = useCallback(
    (id: number): string | null => {
      if (!caseId) return `r${id}`;
      for (const [k, v] of Object.entries(artifactResult)) if (v === id) return k;
      return null;
    },
    [caseId, artifactResult],
  );
  const timelineRows = useMemo(() => {
    const m = new Map<string, Set<number>>();
    for (const e of timeline.events) m.set(e.source.key, (m.get(e.source.key) ?? new Set<number>()).add(e.source.rowIndex));
    return m;
  }, [timeline]);

  const openEntry = useCallback(
    (e: Entry, beside: boolean) => {
      if (caseId) {
        const a = artifacts.find((x) => x.id === e.key);
        if (a) openArtifact(a, artifacts, beside);
      } else show(Number(e.key.slice(1)), beside);
    },
    [caseId, artifacts, openArtifact, show],
  );
  const removeEntry = useCallback(
    (e: Entry) => {
      const a = artifacts.find((x) => x.id === e.key);
      if (a) removeArtifact(a);
    },
    [artifacts, removeArtifact],
  );

  const addToTimeline = (result: WorkResult, row: Row, columns: Column[], table: string | null, rowIndex: number) => {
    const key = keyOfResult(result.id);
    if (!key || rowIndex < 0) return;
    const entry = entries.find((x) => x.key === key);
    setPending({
      row,
      columns,
      source: { key, fileName: result.fileName, path: entry?.path ?? result.fileName, parser: result.parser?.name ?? '', table, rowIndex },
    });
  };
  const openSource = (e: TimelineEvent) => {
    const entry = entries.find((x) => x.key === e.source.key);
    if (!entry) {
      setCaseError(
        `${e.source.path || e.source.fileName} is no longer ${caseId ? 'in this case' : 'open in this session'}, so the event cannot be opened at its source.`,
      );
      return;
    }
    setView('artifacts');
    openEntry(entry, false);
    setFocus({ key: e.source.key, index: e.source.rowIndex, nonce: Date.now() });
  };

  const describe = (e: Entry) => {
    const rid = resultOf(e.key);
    const r = rid === undefined ? undefined : resultById.get(rid);
    const a = caseId ? artifacts.find((x) => x.id === e.key) : undefined;
    const logs = a ? logsFor(a, artifacts).length : 0;
    const kind = e.kind ? knownById.get(e.kind) : undefined;
    return (
      <>
        {r?.error ? (
          <em>unrecognised</em>
        ) : r ? (
          <>
            {r.parser?.ezTool} · {r.rows?.length.toLocaleString()} rows
          </>
        ) : rid !== undefined ? (
          'reading…'
        ) : kind ? (
          `${kind.ezTool} · ${bytes(e.size)}`
        ) : (
          <em>not recognised · {bytes(e.size)}</em>
        )}
        {logs > 0 && ` · +${logs} log${logs > 1 ? 's' : ''}`}
      </>
    );
  };

  const closePane = (i: number) => {
    const next = panes.filter((_, j) => j !== i);
    panesRef.current = next;
    activeRef.current = 0;
    setPanes(next);
    setActivePane(0);
  };

  // Dragging the bar between the two panes.
  const startSplit = (e: React.PointerEvent<HTMLDivElement>) => {
    const box = mainArea.current?.getBoundingClientRect();
    if (!box || e.button !== 0) return;
    e.preventDefault();
    const bar = e.currentTarget;
    bar.setPointerCapture(e.pointerId);
    bar.classList.add('dragging');
    const move = (ev: PointerEvent) => setSplit(Math.max(0.15, Math.min(0.85, (ev.clientX - box.left) / box.width)));
    const stop = () => {
      bar.classList.remove('dragging');
      bar.removeEventListener('pointermove', move);
      bar.removeEventListener('pointerup', stop);
      bar.removeEventListener('pointercancel', stop);
    };
    bar.addEventListener('pointermove', move);
    bar.addEventListener('pointerup', stop);
    bar.addEventListener('pointercancel', stop);
  };

  const splitView = panes.length > 1;

  return (
    <ZoneContext value={zone}>
    <div
      className={`app${dragging ? ' dragging' : ''}`}
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        // Folders are walked, so a whole KAPE collection can be dropped at once.
        droppedFiles(e.dataTransfer.items)
          .then(addIncoming)
          .catch((err: Error) => setCaseError(`The drop could not be read: ${err.message}`));
      }}
    >
      <header className="topbar">
        <div className="brand">
          <Logo busy={busy > 0} />
          <div>
            <h1 className="wordmark" aria-label="4NSEC">
              <span className="four">4</span>
              <span className="rest">
                N<span className="glitch-s" data-z="Z">S</span>EC
              </span>
            </h1>
            <p className="tagline">Artifact forensics in your browser · every byte is parsed in this tab, nothing is uploaded</p>
          </div>
        </div>
        <div className="segmented view-switch" role="radiogroup" aria-label="View">
          <button type="button" role="radio" aria-checked={view === 'artifacts'} className={view === 'artifacts' ? 'on' : ''} onClick={() => setView('artifacts')}>
            Artifacts
          </button>
          <button type="button" role="radio" aria-checked={view === 'timeline'} className={view === 'timeline' ? 'on' : ''} onClick={() => setView('timeline')}>
            Timeline{timeline.events.length ? ` (${timeline.events.length})` : ''}
          </button>
          <button type="button" role="radio" aria-checked={view === 'collect'} className={view === 'collect' ? 'on' : ''} onClick={() => setView('collect')}>
            Collect
          </button>
        </div>
        <span className="spacer" />
        <button
          type="button"
          className={`zone-chip${zone === 'UTC' ? '' : ' shifted'}`}
          title="Every time on screen is shown in this zone, with its offset. Evidence is kept in UTC; CSV and JSON exports are UTC. Change it in Settings."
          onClick={() => setSettingsOpen(true)}
        >
          Times: {zone}
        </button>
        <div className="settings">
          <button type="button" className="icon-btn" aria-expanded={settingsOpen} aria-label="Settings" onClick={() => setSettingsOpen((o) => !o)}>
            ⚙
          </button>
          {settingsOpen && (
            <div className="settings-pop" role="dialog" aria-label="Settings">
              <div className="setting">
                <span>Theme colour</span>
                <input type="color" value={accent} onChange={(e) => setAccent(e.target.value)} aria-label="Theme colour" />
                <button type="button" onClick={() => setAccent(DEFAULT_ACCENT)}>
                  Reset
                </button>
              </div>
              <div className="setting">
                <span>Row details</span>
                <div className="segmented" role="radiogroup" aria-label="Row details position">
                  {(['bottom', 'left', 'right'] as const).map((p) => (
                    <button
                      key={p}
                      type="button"
                      role="radio"
                      aria-checked={position === p}
                      className={position === p ? 'on' : ''}
                      onClick={() => setPosition(p)}
                    >
                      {p[0].toUpperCase() + p.slice(1)}
                    </button>
                  ))}
                </div>
              </div>
              <div className="setting">
                <span>Show times in</span>
                <select value={zone} onChange={(e) => setZone(e.target.value)} aria-label="Show times in">
                  <option value="UTC">UTC (as EZ's tools)</option>
                  {HERE_ZONE !== 'UTC' && <option value={HERE_ZONE}>This computer: {HERE_ZONE}</option>}
                  {ZONES.map((z) => (
                    <option key={z} value={z}>
                      {z}
                    </option>
                  ))}
                </select>
              </div>
              <p className="settings-note">
                Every artifact is read and kept in UTC. The zone changes only what is shown, and each time shows its offset.
                CSV and JSON exports stay UTC; the timeline report uses the zone shown.
              </p>
              <p className="settings-note">Remembered in this browser only.</p>
            </div>
          )}
        </div>
      </header>

      <div className="body">
        <aside>
          <CasePanel
            supported={supported}
            cases={cases}
            active={activeCase}
            artifactCount={listedArtifacts.length}
            storedBytes={artifacts.reduce((n, a) => n + a.size, 0)}
            storage={storage}
            onSelect={switchCase}
            onSave={saveCaseInfo}
            onDelete={removeCase}
          />

          <div className="pick-row">
            <label className="pick">
              <input
                type="file"
                multiple
                onChange={(e) => {
                  if (e.target.files?.length) addIncoming(pickedFiles(e.target.files));
                  e.target.value = '';
                }}
              />
              {caseId ? 'Add files…' : 'Open artifacts…'}
            </label>
            <label className="pick">
              <input
                type="file"
                multiple
                {...{ webkitdirectory: '' }}
                onChange={(e) => {
                  if (e.target.files?.length) addIncoming(pickedFiles(e.target.files));
                  e.target.value = '';
                }}
              />
              {caseId ? 'Add folder…' : 'Open folder…'}
            </label>
          </div>
          <button type="button" className="pick collect-btn" onClick={() => setView('collect')}>
            Collect known artifacts…
          </button>

          {importing && (
            <p className="busy importing">
              Copying into the case… {bytes(importing.done)} of {bytes(importing.total)}
              <button type="button" className="cancel" onClick={() => importAbort.current?.abort()}>
                Cancel
              </button>
            </p>
          )}
          {importNote && !importing && (
            <p className="busy" role="status">
              {importNote}
            </p>
          )}
          {caseError && (
            <p className="bigwarn" role="alert">
              {caseError}
            </p>
          )}
          {busy > 0 && bigFiles.length > 0 && (
            <p className="bigwarn">
              Large file — this may take a while, and the whole file is still parsed: {bigFiles.join(', ')}
            </p>
          )}
          {busy > 0 && (
            <p className="busy">
              Parsing {busy} file{busy > 1 ? 's' : ''}…
            </p>
          )}

          <ArtifactPanel
            entries={entries}
            panesOf={panesOf}
            activeKey={activeKey}
            describe={describe}
            onOpen={openEntry}
            onRemove={caseId ? removeEntry : undefined}
          />

          {caseId && artifacts.length === 0 && !importing && (
            <p className="hint">
              This case is empty. Drop files or a whole folder (a KAPE collection works) anywhere on the page, or use Add
              files / Add folder. They are kept in this browser until you remove them.
            </p>
          )}

          {!caseId && results.length === 0 && (
            <p className="hint">
              Drop a file anywhere on this page. Recognised by content, so a carved or renamed artifact still works:
              <span className="kinds">
                {known
                  .filter((p) => !p.manual)
                  .map((p) => (
                    <span key={p.id}>
                      {p.name}
                      {p.extensions.length > 0 && <code>{p.extensions.join(' ')}</code>}
                    </span>
                  ))}
              </span>
              {known.some((p) => p.manual) && (
                <span className="kinds-note">
                  Read a hive again with <strong>Read as</strong> for{' '}
                  {known
                    .filter((p) => p.manual)
                    .map((p) => p.name)
                    .join(' and ')}
                  .
                </span>
              )}
            </p>
          )}
        </aside>

        {view === 'collect' && (
          <main>
            <Collect parsers={known} inCase={!!caseId} onPick={addIncoming} />
          </main>
        )}
        {view === 'timeline' && (
          <main>
            <TimelineView
              timeline={timeline}
              onChange={setTimeline}
              onOpenSource={openSource}
              persisted={!!caseId}
              report={{
                caseName: activeCase?.name ?? '',
                customer: activeCase?.customer ?? '',
                reference: activeCase?.reference ?? '',
                examiner: activeCase?.examiner ?? '',
                notes: activeCase?.notes ?? '',
              }}
            />
          </main>
        )}
        <main className={`panes${splitView ? ' split' : ''}`} ref={mainArea} hidden={view !== 'artifacts'}>
          {panes.map((p, i) => {
            const result = p.id === null ? undefined : resultById.get(p.id);
            const label = result?.fileName ?? (p.id !== null ? 'Reading…' : 'Empty pane');
            return (
              <Fragment key={p.pid}>
                {i === 1 && (
                  <div
                    className="pane-divider"
                    role="separator"
                    aria-orientation="vertical"
                    aria-label="Resize the panes"
                    title="Drag to resize · double-click to even out"
                    onPointerDown={startSplit}
                    onDoubleClick={() => setSplit(0.5)}
                  />
                )}
                <section
                  className={`pane${splitView && i === activePane ? ' active' : ''}`}
                  style={splitView ? { flexBasis: `${(i === 0 ? split : 1 - split) * 100}%` } : undefined}
                  onPointerDownCapture={() => {
                    activeRef.current = i;
                    setActivePane(i);
                  }}
                  onFocusCapture={() => {
                    activeRef.current = i;
                    setActivePane(i);
                  }}
                  aria-label={splitView ? `${i === 0 ? 'Left' : 'Right'} pane: ${label}` : undefined}
                >
                  <Viewer
                    result={result}
                    waiting={p.id !== null && !result}
                    known={known}
                    onReparse={reparse}
                    position={position}
                    sizes={sizes}
                    onSizes={setSizes}
                    builderOpen={builderOpen}
                    onBuilderOpen={setBuilderOpen}
                    saved={saved}
                    onSaved={onSaved}
                    pane={splitView ? { label: `${i === 0 ? 'L' : 'R'} · ${label}`, active: i === activePane, onClose: () => closePane(i) } : undefined}
                    onAddToTimeline={result ? (row, columns, table, rowIndex) => addToTimeline(result, row, columns, table, rowIndex) : undefined}
                    focus={result && focus && keyOfResult(result.id) === focus.key ? { index: focus.index, nonce: focus.nonce } : null}
                    onTimeline={result ? timelineRows.get(keyOfResult(result.id) ?? '') : undefined}
                  />
                </section>
              </Fragment>
            );
          })}
        </main>
      </div>

      {pending && (
        <AddEventDialog
          pending={pending}
          timeline={timeline}
          lastLane={lastLane}
          onCancel={() => setPending(null)}
          onAdd={(e) => {
            setTimeline({ lanes: timeline.lanes.includes(e.lane) ? timeline.lanes : [...timeline.lanes, e.lane], events: [...timeline.events, e] });
            setLastLane(e.lane);
            setPending(null);
          }}
        />
      )}
    </div>
    </ZoneContext>
  );
}
