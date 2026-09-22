import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { Row } from './core/types';
import { Detail } from './ui/Detail';
import { Grid } from './ui/Grid';
import { Logo } from './ui/Logo';
import { SigmaPanel } from './ui/SigmaPanel';
import { bytes, download, toCsv, toJson } from './ui/format';
import { queryError } from './ui/query';
import { compileSigma, SigmaError, type SigmaRule } from './ui/sigma';
import {
  isColour,
  isPosition,
  isSavedList,
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

  const [position, setPosition] = useState<DetailPosition>(() =>
    read('detailPosition', 'bottom', isPosition),
  );
  const [accent, setAccent] = useState(() => read('accent', DEFAULT_ACCENT, isColour));
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
  const opened = useRef(new Map<number, { file: File; siblings?: File[] }>());
  const worker = useRef<Worker>(null);

  useEffect(() => {
    const w = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' });
    w.onmessage = (e: MessageEvent<WorkResult | WorkerReady>) => {
      if ('ready' in e.data) {
        setKnown(e.data.parsers);
        return;
      }
      const result = e.data;
      setResults((rs) => [...rs, result]);
      setBusy((n) => n - 1);
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

  const ingest = useCallback((files: FileList | File[]) => {
    const all = [...files];
    for (const file of all) {
      // A registry transaction log is not an artifact in its own right; it is
      // part of the hive beside it. Opening one on its own says nothing, so it
      // is handed to that hive instead of being parsed separately.
      if (/\.log[12]?$/i.test(file.name)) {
        const hive = file.name.replace(/\.log[12]?$/i, '');
        if (all.some((f) => f.name.toLowerCase() === hive.toLowerCase())) continue;
      }
      setBusy((n) => n + 1);
      // Everything in the file is parsed regardless of size — nothing is
      // truncated. But past this point it takes long enough that silence looks
      // like a hang, so say so rather than leave the analyst guessing.
      if (file.size >= 64 * 1024 * 1024) {
        setBigFiles((b) => [...b, `${file.name} (${bytes(file.size)})`]);
      }
      const siblings = all.filter(
        (f) => f !== file && f.name.toLowerCase().startsWith(`${file.name.toLowerCase()}.log`),
      );
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

  const current = results.find((r) => r.id === sel);
  const columns = useMemo(() => current?.parser?.columns ?? [], [current]);
  const parserId = current?.parser?.id ?? '';

  /** Reads the selected artifact again with a parser the analyst picked. */
  const reparse = useCallback((id: number, pid: string) => {
    const source = opened.current.get(id);
    if (!source) return;
    setBusy((n) => n + 1);
    setRow(null);
    setColFilters({});
    // Replaces the row in place: the same file read two ways is one artifact
    // with a different question asked of it, not two artifacts.
    setResults((rs) => rs.filter((r) => r.id !== id));
    worker.current?.postMessage({
      id,
      file: source.file,
      siblings: source.siblings,
      parserId: pid,
    } satisfies WorkRequest);
  }, []);

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
    () => (activeRule && current?.rows ? current.rows.filter(activeRule.test).length : 0),
    [activeRule, current],
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
    if (!name || !current?.parser) return;
    const next = upsert(saved, {
      name,
      parserId: current.parser.id,
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
        if (e.dataTransfer.files.length) ingest(e.dataTransfer.files);
      }}
    >
      <header className="topbar">
        <div className="brand">
          <Logo busy={busy > 0} />
          <div>
            <h1 className="wordmark" aria-label="4ENSICS">
              <span className="four">4</span>
              <span className="rest">ENSICS</span>
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
          <label className="pick">
            <input
              type="file"
              multiple
              onChange={(e) => {
                if (e.target.files?.length) ingest(e.target.files);
                e.target.value = '';
              }}
            />
            Open artifacts…
          </label>

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

          <ul className="files">
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

          {results.length === 0 && (
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
              <p>No artifact selected.</p>
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
                    download(`${current.fileName}.csv`, toCsv(columns, current.rows!), 'text/csv')
                  }
                >
                  CSV
                </button>
                <button
                  type="button"
                  onClick={() =>
                    download(`${current.fileName}.json`, toJson(current.rows!), 'application/json')
                  }
                >
                  JSON
                </button>
              </div>

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
                  total={current.rows.length}
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

              <div className={`workspace ${position}`}>
                <Grid
                  columns={columns}
                  rows={current.rows}
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
                  <Detail
                    columns={columns}
                    row={row}
                    position={position}
                    onClose={() => setRow(null)}
                  />
                )}
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
}
