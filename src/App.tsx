import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { Row } from './core/types';
import { Detail } from './ui/Detail';
import { Grid } from './ui/Grid';
import { Logo } from './ui/Logo';
import { QueryBuilder } from './ui/QueryBuilder';
import { CasePanel } from './ui/CasePanel';
import {
  addToCase,
  artifactFile,
  baseName,
  casesSupported,
  companionsFor,
  deleteCase,
  dirName,
  droppedFiles,
  isPairedLog,
  listArtifacts,
  listCases,
  logsFor,
  pickedFiles,
  removeArtifacts,
  saveCase,
  setArtifactParser,
  storageUse,
  type CaseArtifact,
  type CaseInfo,
  type Incoming,
} from './ui/cases';
import { SigmaPanel } from './ui/SigmaPanel';
import { bytes, download, toCsv, toJson } from './ui/format';
import { queryError } from './ui/query';
import { compileSigma, SigmaError, type SigmaRule } from './ui/sigma';
import {
  DEFAULT_DETAIL_SIZES,
  isColour,
  isFlag,
  isPosition,
  isSavedList,
  isSizes,
  read,
  upsert,
  write,
  type DetailPosition,
  type SavedFilter,
} from './ui/storage';
import type { ParserInfo, WorkRequest, WorkResult, WorkerReady } from './worker';

let nextId = 1;

/** The accent the Phishing Email Analyzer ships with. */
const DEFAULT_ACCENT = '#9fef00';

export default function App() {
  const [results, setResults] = useState<WorkResult[]>([]);
  const [sel, setSel] = useState<number | null>(null);
  const [row, setRow] = useState<Row | null>(null);
  const [search, setSearch] = useState('');
  const [colFilters, setColFilters] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(0);
  const [bigFiles, setBigFiles] = useState<string[]>([]);
  const [dragging, setDragging] = useState(false);
  const [known, setKnown] = useState<ParserInfo[]>([]);
  const [tableId, setTableId] = useState('');

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

  const [position, setPosition] = useState<DetailPosition>(() =>
    read('detailPosition', 'bottom', isPosition),
  );
  const [accent, setAccent] = useState(() => read('accent', DEFAULT_ACCENT, isColour));
  const [sizes, setSizes] = useState(() => read('detailSizes', DEFAULT_DETAIL_SIZES, isSizes));
  const [builderOpen, setBuilderOpen] = useState(() => read('builderOpen', true, isFlag));
  const workspace = useRef<HTMLDivElement>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);

  const [saved, setSaved] = useState<SavedFilter[]>(() => read('savedFilters', [], isSavedList));
  const [saving, setSaving] = useState<string | null>(null);
  const [appliedSaved, setAppliedSaved] = useState('');

  const [sigmaOpen, setSigmaOpen] = useState(false);
  const [sigmaText, setSigmaText] = useState('');
  /** The rule text that is running, as opposed to what is being edited. */
  const [sigmaActive, setSigmaActive] = useState<string | null>(null);
  const [sigmaRule, setSigmaRule] = useState<SigmaRule | null>(null);
  const [sigmaError, setSigmaError] = useState<string | null>(null);
  const [sigmaWorking, setSigmaWorking] = useState(false);
  /** Bumped by every press of Run, so running the same text again re-runs it. */
  const [sigmaRuns, setSigmaRuns] = useState(0);

  // The file behind each result, so it can be read again as something else.
  // Some artifacts are a structure inside another: shell bags live in a
  // registry hive, and which of the two you want is a question only the
  // analyst can answer.
  const opened = useRef(new Map<number, { file: File; siblings?: File[]; artifactId?: string }>());
  const worker = useRef<Worker>(null);

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
      setResults((rs) => [...rs, result]);
      setSel((s) => s ?? result.id);
    };
    worker.current = w;
    return () => w.terminate();
  }, []);

  useEffect(() => {
    document.documentElement.style.setProperty('--accent', accent);
    write('accent', accent);
  }, [accent]);

  useEffect(() => {
    write('detailPosition', position);
  }, [position]);

  useEffect(() => {
    write('detailSizes', sizes);
  }, [sizes]);

  useEffect(() => {
    write('builderOpen', builderOpen);
  }, [builderOpen]);

  /** The details' size along the axis they sit on, kept clear of the grid. */
  const resizeDetail = (size: number) => {
    const box = workspace.current?.getBoundingClientRect();
    const room = box ? (position === 'bottom' ? box.height : box.width) - 120 : Infinity;
    const clamped = Math.round(Math.max(120, Math.min(size, room)));
    setSizes((s) => (position === 'bottom' ? { ...s, bottom: clamped } : { ...s, side: clamped }));
  };
  const detailSize = position === 'bottom' ? sizes.bottom : sizes.side;

  // Dragging the bar between the grid and the details. Pointer capture keeps
  // the drag going when the pointer leaves the thin bar.
  const startResize = (e: React.PointerEvent<HTMLDivElement>) => {
    const box = workspace.current?.getBoundingClientRect();
    if (!box || e.button !== 0) return;
    e.preventDefault();
    const bar = e.currentTarget;
    bar.setPointerCapture(e.pointerId);
    bar.classList.add('dragging');
    const move = (ev: PointerEvent) =>
      resizeDetail(
        position === 'bottom'
          ? box.bottom - ev.clientY
          : position === 'right'
            ? box.right - ev.clientX
            : ev.clientX - box.left,
      );
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

  const keyResize = (e: React.KeyboardEvent) => {
    const grow: Record<DetailPosition, [string, string]> = {
      bottom: ['ArrowUp', 'ArrowDown'],
      right: ['ArrowLeft', 'ArrowRight'],
      left: ['ArrowRight', 'ArrowLeft'],
    };
    const [more, less] = grow[position];
    if (e.key !== more && e.key !== less) return;
    e.preventDefault();
    resizeDetail(detailSize + (e.key === more ? 24 : -24));
  };

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
      opened.current.set(id, {
        file,
        siblings: siblings.length > 0 ? siblings : undefined,
      });
      worker.current?.postMessage({
        id,
        file,
        siblings: siblings.length > 0 ? siblings : undefined,
      } satisfies WorkRequest);
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

  // The chosen case's artifacts, read from storage whenever the case changes.
  useEffect(() => {
    write('activeCase', caseId);
    if (!caseId || !supported) return;
    let live = true;
    listArtifacts(caseId)
      .then((list) => live && setArtifacts(list))
      .catch(() => live && setArtifacts([]));
    return () => {
      live = false;
    };
  }, [caseId, supported]);

  /** Switching case starts from a clean page: what was open belonged to the other case. */
  const switchCase = useCallback((id: string | null) => {
    opened.current.clear();
    setResults([]);
    setSel(null);
    setRow(null);
    setArtifactResult({});
    setArtifacts([]);
    setCaseError(null);
    setCaseId(id);
  }, []);

  /** Reads a stored artifact, with its transaction logs when it is a hive. */
  const openArtifact = useCallback(
    async (a: CaseArtifact, list: CaseArtifact[]) => {
      if (!caseId) return;
      const existing = artifactResult[a.id];
      if (existing !== undefined) {
        setSel(existing);
        setRow(null);
        return;
      }
      try {
        const file = await artifactFile(caseId, a);
        const logs = await Promise.all(companionsFor(a, list).map((l) => artifactFile(caseId, l)));
        const id = nextId++;
        opened.current.set(id, { file, siblings: logs.length ? logs : undefined, artifactId: a.id });
        setArtifactResult((m) => ({ ...m, [a.id]: id }));
        setBusy((n) => n + 1);
        setSel(id);
        setRow(null);
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
    [caseId, artifactResult],
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
        setSel((s) => (s === rid ? null : s));
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

  const activeCase = cases.find((c) => c.id === caseId) ?? null;
  const knownById = useMemo(() => new Map(known.map((p) => [p.id, p])), [known]);
  // A hive's transaction logs are read with it, not listed on their own.
  const listedArtifacts = useMemo(
    () => artifacts.filter((a) => !isPairedLog(a, artifacts)).sort((a, b) => a.path.localeCompare(b.path)),
    [artifacts],
  );

  const current = results.find((r) => r.id === sel);

  // An artifact with several kinds of record shows one table at a time, as
  // his tools write one CSV per kind. Only tables with rows are offered, so
  // an Amcache hive shows its own layout's tables and not the other one's.
  const tables = useMemo(() => {
    const declared = current?.parser?.tables;
    if (!declared || !current?.rows) return [];
    const counts = new Map<unknown, number>();
    for (const r of current.rows) counts.set(r.table, (counts.get(r.table) ?? 0) + 1);
    const withRows = declared.filter((t) => counts.has(t.id));
    return (withRows.length > 0 ? withRows : declared.slice(0, 1)).map((t) => ({
      ...t,
      count: counts.get(t.id) ?? 0,
    }));
  }, [current]);
  const table = tables.find((t) => t.id === tableId) ?? tables[0];
  const columns = useMemo(() => table?.columns ?? current?.parser?.columns ?? [], [table, current]);
  const rows = useMemo(
    () => (table ? (current?.rows ?? []).filter((r) => r.table === table.id) : (current?.rows ?? [])),
    [table, current],
  );
  // Saved filters belong to a table, since column filters name its columns.
  const parserId = current?.parser ? current.parser.id + (table ? `/${table.id}` : '') : '';

  /** Reads the selected artifact again with a parser the analyst picked. */
  const reparse = useCallback((id: number, pid: string) => {
    const source = opened.current.get(id);
    if (!source) return;
    setBusy((n) => n + 1);
    setRow(null);
    setColFilters({});
    setTableId('');
    // Replaces the row in place: the same file read two ways is one artifact
    // with a different question asked of it, not two artifacts.
    setResults((rs) => rs.filter((r) => r.id !== id));
    worker.current?.postMessage({
      id,
      file: source.file,
      siblings: source.siblings,
      parserId: pid,
    } satisfies WorkRequest);
    // In a case the choice is kept, so the artifact opens the same way next time.
    if (caseId && source.artifactId) {
      setArtifactParser(caseId, source.artifactId, pid).then(setArtifacts).catch(() => undefined);
    }
  }, [caseId]);

  // A rule is compiled against the columns of the artifact it runs on, so a
  // rule left running is compiled again when the analyst moves to another
  // artifact. That is what lets one rule be run across a dozen event logs.
  useEffect(() => {
    let live = true;
    if (!sigmaActive || columns.length === 0) return;
    compileSigma(sigmaActive, columns)
      .then((rule) => {
        if (!live) return;
        setSigmaRule(rule);
        setSigmaError(null);
      })
      .catch((e: unknown) => {
        if (!live) return;
        setSigmaRule(null);
        setSigmaError(e instanceof SigmaError ? e.message : `the rule could not be run: ${String(e)}`);
      })
      .finally(() => live && setSigmaWorking(false));
    return () => {
      live = false;
    };
  }, [sigmaActive, columns, sigmaRuns]);

  // A compiled rule only counts while its text is the one running; clearing the
  // rule makes it inert at once, without waiting for anything.
  const activeRule = sigmaActive ? sigmaRule : null;

  const sigmaMatched = useMemo(
    () => (activeRule ? rows.filter(activeRule.test).length : 0),
    [activeRule, rows],
  );

  const runRule = () => {
    setSigmaError(null);
    setSigmaWorking(true);
    setSigmaActive(sigmaText);
    setSigmaRuns((n) => n + 1);
  };

  const clearRule = () => {
    setSigmaActive(null);
    setSigmaRule(null);
    setSigmaError(null);
  };

  const available = saved.filter((f) => f.parserId === parserId);

  const applySaved = (name: string) => {
    const f = available.find((x) => x.name === name);
    setAppliedSaved(name);
    if (!f) return;
    setSearch(f.search);
    setColFilters(f.columns);
    if (f.sigma) {
      setSigmaText(f.sigma);
      setSigmaActive(f.sigma);
      setSigmaOpen(true);
    } else {
      clearRule();
    }
  };

  const commitSave = () => {
    const name = (saving ?? '').trim();
    if (!name || !parserId) return;
    const next = upsert(saved, {
      name,
      parserId,
      search,
      columns: Object.fromEntries(Object.entries(colFilters).filter(([, v]) => v.trim())),
      sigma: sigmaActive,
    });
    setSaved(next);
    write('savedFilters', next);
    setAppliedSaved(name);
    setSaving(null);
  };

  const deleteSaved = (name: string) => {
    const next = saved.filter((f) => !(f.name === name && f.parserId === parserId));
    setSaved(next);
    write('savedFilters', next);
    setAppliedSaved('');
  };

  const searchProblem = search.trim() && columns.length ? queryError(search, columns) : null;
  const hasFilter =
    search.trim() !== '' || Object.values(colFilters).some((v) => v.trim()) || !!sigmaActive;

  return (
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
            <p className="tagline">
              Artifact forensics in your browser · every byte is parsed in this tab, nothing is
              uploaded
            </p>
          </div>
        </div>
        <span className="spacer" />
        <div className="settings">
          <button
            type="button"
            className="icon-btn"
            aria-expanded={settingsOpen}
            aria-label="Settings"
            onClick={() => setSettingsOpen((o) => !o)}
          >
            ⚙
          </button>
          {settingsOpen && (
            <div className="settings-pop" role="dialog" aria-label="Settings">
              <div className="setting">
                <span>Theme colour</span>
                <input
                  type="color"
                  value={accent}
                  onChange={(e) => setAccent(e.target.value)}
                  aria-label="Theme colour"
                />
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
              Large file — this may take a while, and the whole file is still parsed:{' '}
              {bigFiles.join(', ')}
            </p>
          )}
          {busy > 0 && (
            <p className="busy">
              Parsing {busy} file{busy > 1 ? 's' : ''}…
            </p>
          )}

          {caseId && (
            <ul className="files">
              {listedArtifacts.map((a) => {
                const rid = artifactResult[a.id];
                const r = rid === undefined ? undefined : results.find((x) => x.id === rid);
                const kind = knownById.get(a.parserId ?? a.detected ?? '');
                const logs = logsFor(a, artifacts).length;
                return (
                  <li key={a.id} className="artifact">
                    <button
                      type="button"
                      className={rid !== undefined && rid === sel ? 'on' : ''}
                      title={a.path}
                      onClick={() => {
                        setSearch('');
                        setColFilters({});
                        setTableId('');
                        setAppliedSaved('');
                        openArtifact(a, artifacts);
                      }}
                    >
                      <span className="fn">{baseName(a.path)}</span>
                      {dirName(a.path) && <span className="dir">{dirName(a.path)}</span>}
                      <span className="meta">
                        {r?.error ? (
                          <em>unrecognised</em>
                        ) : r ? (
                          <>
                            {r.parser?.ezTool} · {r.rows?.length.toLocaleString()} rows
                          </>
                        ) : rid !== undefined ? (
                          'reading…'
                        ) : kind ? (
                          `${kind.ezTool} · ${bytes(a.size)}`
                        ) : (
                          <em>not recognised · {bytes(a.size)}</em>
                        )}
                        {logs > 0 && ` · +${logs} log${logs > 1 ? 's' : ''}`}
                      </span>
                    </button>
                    <button
                      type="button"
                      className="remove"
                      aria-label={`Remove ${a.path} from the case`}
                      title="Remove from the case"
                      onClick={() => removeArtifact(a)}
                    >
                      ×
                    </button>
                  </li>
                );
              })}
            </ul>
          )}

          {caseId && artifacts.length === 0 && !importing && (
            <p className="hint">
              This case is empty. Drop files or a whole folder (a KAPE collection works) anywhere on
              the page, or use Add files / Add folder. They are kept in this browser until you
              remove them.
            </p>
          )}

          <ul className="files" hidden={!!caseId}>
            {results.map((r) => (
              <li key={r.id}>
                <button
                  type="button"
                  className={r.id === sel ? 'on' : ''}
                  onClick={() => {
                    setSel(r.id);
                    setRow(null);
                    setSearch('');
                    setColFilters({});
                    setTableId('');
                    setAppliedSaved('');
                  }}
                >
                  <span className="fn">{r.fileName}</span>
                  <span className="meta">
                    {r.error ? (
                      <em>unrecognised</em>
                    ) : (
                      <>
                        {r.parser?.ezTool} · {r.rows?.length.toLocaleString()} rows
                      </>
                    )}
                  </span>
                </button>
              </li>
            ))}
          </ul>

          {!caseId && results.length === 0 && (
            <p className="hint">
              Drop a file anywhere on this page. Recognised by content, so a carved or renamed
              artifact still works:
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

        <main>
          {!current && (
            <div className="empty">
              <Logo size={96} busy={busy > 0} />
              <p>{sel !== null && busy > 0 ? 'Reading…' : 'No artifact selected.'}</p>
            </div>
          )}

          {current?.error && (
            <div className="empty error">
              <strong>{current.fileName}</strong>
              <p>{current.error}</p>
            </div>
          )}

          {current?.parser && current.rows && (
            <>
              <div className="toolbar">
                <input
                  className={`search${searchProblem ? ' bad' : ''}`}
                  placeholder="Search — 4624 OR 4625 · TargetUserName=admin · -svchost · CommandLine contains mimikatz"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  aria-invalid={!!searchProblem}
                  title={searchProblem ?? undefined}
                />
                <button
                  type="button"
                  className={sigmaOpen || sigmaActive ? 'on' : ''}
                  onClick={() => setSigmaOpen((o) => !o)}
                >
                  Sigma{sigmaActive ? ' ●' : ''}
                </button>
                <button
                  type="button"
                  className={builderOpen ? 'on' : ''}
                  onClick={() => setBuilderOpen((o) => !o)}
                  title="Build the search a condition at a time"
                >
                  Builder
                </button>

                <select
                  className="saved"
                  value={appliedSaved}
                  onChange={(e) => applySaved(e.target.value)}
                  aria-label="Saved filters"
                >
                  <option value="">
                    {available.length ? `Saved filters (${available.length})` : 'No saved filters'}
                  </option>
                  {available.map((f) => (
                    <option key={f.name} value={f.name}>
                      {f.name}
                      {f.sigma ? ' · rule' : ''}
                    </option>
                  ))}
                </select>
                {appliedSaved && (
                  <button
                    type="button"
                    onClick={() => deleteSaved(appliedSaved)}
                    title={`Delete the saved filter "${appliedSaved}"`}
                  >
                    Delete
                  </button>
                )}
                {saving === null ? (
                  <button
                    type="button"
                    disabled={!hasFilter}
                    title={hasFilter ? 'Keep this search, the column filters and any rule' : 'Nothing to save yet'}
                    onClick={() => setSaving(appliedSaved)}
                  >
                    Save filter
                  </button>
                ) : (
                  <span className="save-as">
                    <input
                      autoFocus
                      placeholder="Name this filter"
                      value={saving}
                      onChange={(e) => setSaving(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') commitSave();
                        if (e.key === 'Escape') setSaving(null);
                      }}
                      aria-label="Filter name"
                    />
                    <button type="button" className="primary" onClick={commitSave} disabled={!saving.trim()}>
                      Save
                    </button>
                    <button type="button" onClick={() => setSaving(null)}>
                      Cancel
                    </button>
                  </span>
                )}

                <span className="spacer" />
                <label className="parseas">
                  Read as
                  <select
                    value={current.parser.id}
                    onChange={(e) => reparse(current.id, e.target.value)}
                  >
                    {known.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name} ({p.ezTool})
                      </option>
                    ))}
                  </select>
                </label>
                <span className="stat">
                  {bytes(current.fileSize)} · {current.ms} ms
                </span>
                <button
                  type="button"
                  onClick={() =>
                    download(
                      `${current.fileName}${table ? `_${table.label}` : ''}.csv`,
                      toCsv(columns, rows),
                      'text/csv',
                    )
                  }
                >
                  CSV
                </button>
                <button
                  type="button"
                  onClick={() =>
                    download(
                      `${current.fileName}${table ? `_${table.label}` : ''}.json`,
                      toJson(rows),
                      'application/json',
                    )
                  }
                >
                  JSON
                </button>
              </div>

              {builderOpen && (
                <QueryBuilder columns={columns} rows={rows} value={search} onChange={setSearch} />
              )}

              {tables.length > 0 && (
                <div className="tables" role="tablist" aria-label="Tables in this artifact">
                  {tables.map((t) => (
                    <button
                      key={t.id}
                      type="button"
                      role="tab"
                      aria-selected={t.id === table?.id}
                      className={t.id === table?.id ? 'on' : ''}
                      onClick={() => {
                        setTableId(t.id);
                        setRow(null);
                        setColFilters({});
                        setAppliedSaved('');
                      }}
                    >
                      {t.label} <span className="count">{t.count.toLocaleString()}</span>
                    </button>
                  ))}
                </div>
              )}

              {sigmaOpen && (
                <SigmaPanel
                  text={sigmaText}
                  onText={setSigmaText}
                  onRun={runRule}
                  onClear={clearRule}
                  onClose={() => setSigmaOpen(false)}
                  rule={activeRule}
                  error={sigmaError}
                  working={sigmaWorking}
                  matched={sigmaMatched}
                  total={rows.length}
                />
              )}

              {!!current.warnings?.length && (
                <details className="warnings">
                  <summary>
                    {current.warnings.length} warning{current.warnings.length > 1 ? 's' : ''} about
                    this artifact
                  </summary>
                  <ul>
                    {current.warnings.map((w, i) => (
                      <li key={i}>
                        <code>0x{w.offset.toString(16)}</code> {w.message}
                      </li>
                    ))}
                  </ul>
                </details>
              )}

              <div className={`workspace ${position}`} ref={workspace}>
                <Grid
                  columns={columns}
                  rows={rows}
                  filter={search}
                  colFilters={colFilters}
                  onColFilters={setColFilters}
                  extra={activeRule?.test ?? null}
                  extraLabel={activeRule ? `Sigma: ${activeRule.title}` : undefined}
                  // A parser that stopped early says so in a warning. Surface
                  // that in the footer too, so completeness is never implied
                  // over a truncated artifact.
                  partial={current.warnings?.some((w) =>
                    /partial|cap |cancelled|truncat/i.test(w.message),
                  )}
                  onSelect={setRow}
                />
                {row && (
                  <>
                    <div
                      className={`splitter ${position}`}
                      role="separator"
                      aria-orientation={position === 'bottom' ? 'horizontal' : 'vertical'}
                      aria-label="Resize the row details"
                      aria-valuenow={detailSize}
                      tabIndex={0}
                      title="Drag to resize · double-click to reset"
                      onPointerDown={startResize}
                      onKeyDown={keyResize}
                      onDoubleClick={() =>
                        setSizes((s) =>
                          position === 'bottom'
                            ? { ...s, bottom: DEFAULT_DETAIL_SIZES.bottom }
                            : { ...s, side: DEFAULT_DETAIL_SIZES.side },
                        )
                      }
                    />
                    <Detail
                      columns={columns}
                      row={row}
                      position={position}
                      size={detailSize}
                      onClose={() => setRow(null)}
                    />
                  </>
                )}
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
}
