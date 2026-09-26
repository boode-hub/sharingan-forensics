import { useEffect, useMemo, useRef, useState } from 'react';
import type { Column, Row } from '../core/types';
import type { ParserInfo, WorkResult } from '../worker';
import { Detail } from './Detail';
import { bytes, download, toCsv, toJson } from './format';
import { Grid } from './Grid';
import { Logo } from './Logo';
import { QueryBuilder } from './QueryBuilder';
import { queryError } from './query';
import { compileSigma, SigmaError, type SigmaRule } from './sigma';
import { SigmaPanel } from './SigmaPanel';
import { DEFAULT_DETAIL_SIZES, upsert, type DetailPosition, type DetailSizes, type SavedFilter } from './storage';

/**
 * One artifact on screen: its tables, search, filters, Sigma rule and row
 * details. The main area holds one of these, or two side by side, and each
 * keeps its own search and rule, so an event log and a prefetch file can be
 * worked through together.
 */
export function Viewer({
  result,
  waiting,
  known,
  onReparse,
  position,
  sizes,
  onSizes,
  builderOpen,
  onBuilderOpen,
  saved,
  onSaved,
  pane,
  onAddToTimeline,
  focus,
  onTimeline,
}: {
  result: WorkResult | undefined;
  /** An artifact has been asked for and is still being read. */
  waiting: boolean;
  known: ParserInfo[];
  onReparse: (id: number, parserId: string) => void;
  position: DetailPosition;
  sizes: DetailSizes;
  onSizes: (update: (s: DetailSizes) => DetailSizes) => void;
  builderOpen: boolean;
  onBuilderOpen: (open: boolean) => void;
  saved: SavedFilter[];
  onSaved: (next: SavedFilter[]) => void;
  /** Present when the main area is split: this pane's title bar. */
  pane?: { label: string; active: boolean; onClose: () => void };
  /** Right-click → Add to timeline: the row, its columns, its table and its index among the artifact's rows. */
  onAddToTimeline?: (row: Row, columns: Column[], table: string | null, rowIndex: number) => void;
  /** A row to bring into view (by index among the artifact's rows); the nonce makes asking again move again. */
  focus?: { index: number; nonce: number } | null;
  /** Indexes of this artifact's rows already on the timeline. */
  onTimeline?: Set<number>;
}) {
  const [row, setRow] = useState<Row | null>(null);
  const [search, setSearch] = useState('');
  const [colFilters, setColFilters] = useState<Record<string, string>>({});
  const [tableId, setTableId] = useState('');
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
  const workspace = useRef<HTMLDivElement>(null);
  const [menu, setMenu] = useState<{ row: Row; x: number; y: number } | null>(null);
  const [focusRow, setFocusRow] = useState<Row | null>(null);

  // Another artifact (or the same one read as something else) starts from a
  // clean search. A running Sigma rule stays: that is what lets one rule be
  // run across a dozen event logs.
  const [shown, setShown] = useState(result);
  if (shown !== result) {
    setShown(result);
    setRow(null);
    setSearch('');
    setColFilters({});
    setTableId('');
    setAppliedSaved('');
  }

  // An artifact with several kinds of record shows one table at a time, as
  // his tools write one CSV per kind. Only tables with rows are offered, so
  // an Amcache hive shows its own layout's tables and not the other one's.
  const tables = useMemo(() => {
    const declared = result?.parser?.tables;
    if (!declared || !result?.rows) return [];
    const counts = new Map<unknown, number>();
    for (const r of result.rows) counts.set(r.table, (counts.get(r.table) ?? 0) + 1);
    const withRows = declared.filter((t) => counts.has(t.id));
    return (withRows.length > 0 ? withRows : declared.slice(0, 1)).map((t) => ({
      ...t,
      count: counts.get(t.id) ?? 0,
    }));
  }, [result]);
  const table = tables.find((t) => t.id === tableId) ?? tables[0];
  const columns = useMemo(() => table?.columns ?? result?.parser?.columns ?? [], [table, result]);
  const rows = useMemo(
    () => (table ? (result?.rows ?? []).filter((r) => r.table === table.id) : (result?.rows ?? [])),
    [table, result],
  );
  // A row asked for (a timeline event's source): its table, no filters hiding
  // it, selected and scrolled to.
  const [focused, setFocused] = useState<number | null>(null);
  if (focus && result?.rows && focus.nonce !== focused) {
    setFocused(focus.nonce);
    const r = result.rows[focus.index];
    if (r) {
      if (typeof r.table === 'string') setTableId(r.table);
      setSearch('');
      setColFilters({});
      setAppliedSaved('');
      setRow(r);
      setFocusRow(r);
    }
  }
  const marked = useMemo(
    () => new Set([...(onTimeline ?? [])].map((i) => result?.rows?.[i]).filter((r): r is Row => !!r)),
    [onTimeline, result],
  );

  useEffect(() => {
    if (!menu) return;
    const close = () => setMenu(null);
    const key = (e: KeyboardEvent) => e.key === 'Escape' && setMenu(null);
    window.addEventListener('click', close);
    window.addEventListener('keydown', key);
    window.addEventListener('scroll', close, true);
    return () => {
      window.removeEventListener('click', close);
      window.removeEventListener('keydown', key);
      window.removeEventListener('scroll', close, true);
    };
  }, [menu]);

  // Saved filters belong to a table, since column filters name its columns.
  const parserId = result?.parser ? result.parser.id + (table ? `/${table.id}` : '') : '';

  // A rule is compiled against the columns of the artifact it runs on, so a
  // rule left running is compiled again when the pane moves to another artifact.
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

  // A compiled rule only counts while its text is the one running.
  const activeRule = sigmaActive ? sigmaRule : null;
  const sigmaMatched = useMemo(() => (activeRule ? rows.filter(activeRule.test).length : 0), [activeRule, rows]);

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
    onSaved(
      upsert(saved, {
        name,
        parserId,
        search,
        columns: Object.fromEntries(Object.entries(colFilters).filter(([, v]) => v.trim())),
        sigma: sigmaActive,
      }),
    );
    setAppliedSaved(name);
    setSaving(null);
  };
  const deleteSaved = (name: string) => {
    onSaved(saved.filter((f) => !(f.name === name && f.parserId === parserId)));
    setAppliedSaved('');
  };

  /** The details' size along the axis they sit on, kept clear of the grid. */
  const detailSize = position === 'bottom' ? sizes.bottom : sizes.side;
  const resizeDetail = (size: number) => {
    const box = workspace.current?.getBoundingClientRect();
    const room = box ? (position === 'bottom' ? box.height : box.width) - 120 : Infinity;
    const clamped = Math.round(Math.max(120, Math.min(size, room)));
    onSizes((s) => (position === 'bottom' ? { ...s, bottom: clamped } : { ...s, side: clamped }));
  };
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
        position === 'bottom' ? box.bottom - ev.clientY : position === 'right' ? box.right - ev.clientX : ev.clientX - box.left,
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

  const searchProblem = search.trim() && columns.length ? queryError(search, columns) : null;
  const hasFilter = search.trim() !== '' || Object.values(colFilters).some((v) => v.trim()) || !!sigmaActive;

  return (
    <>
      {pane && (
        <div className={`pane-bar${pane.active ? ' on' : ''}`}>
          <span className="pane-title" title={pane.label}>
            {pane.label}
          </span>
          <button type="button" className="pane-close" aria-label={`Close ${pane.label}`} title="Close this pane" onClick={pane.onClose}>
            ×
          </button>
        </div>
      )}

      {!result && (
        <div className="empty">
          <Logo size={pane ? 64 : 96} busy={waiting} />
          <p>{waiting ? 'Reading…' : pane ? 'Pick an artifact on the left to show it here.' : 'No artifact selected.'}</p>
        </div>
      )}

      {result?.error && (
        <div className="empty error">
          <strong>{result.fileName}</strong>
          <p>{result.error}</p>
        </div>
      )}

      {result?.parser && result.rows && (
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
            <button type="button" className={sigmaOpen || sigmaActive ? 'on' : ''} onClick={() => setSigmaOpen((o) => !o)}>
              Sigma{sigmaActive ? ' ●' : ''}
            </button>
            <button
              type="button"
              className={builderOpen ? 'on' : ''}
              onClick={() => onBuilderOpen(!builderOpen)}
              title="Build the search a condition at a time"
            >
              Builder
            </button>

            <select className="saved" value={appliedSaved} onChange={(e) => applySaved(e.target.value)} aria-label="Saved filters">
              <option value="">{available.length ? `Saved filters (${available.length})` : 'No saved filters'}</option>
              {available.map((f) => (
                <option key={f.name} value={f.name}>
                  {f.name}
                  {f.sigma ? ' · rule' : ''}
                </option>
              ))}
            </select>
            {appliedSaved && (
              <button type="button" onClick={() => deleteSaved(appliedSaved)} title={`Delete the saved filter "${appliedSaved}"`}>
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
              <select value={result.parser.id} onChange={(e) => onReparse(result.id, e.target.value)}>
                {known.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.ezTool})
                  </option>
                ))}
              </select>
            </label>
            <span className="stat">
              {bytes(result.fileSize)} · {result.ms} ms
            </span>
            <button
              type="button"
              onClick={() => download(`${result.fileName}${table ? `_${table.label}` : ''}.csv`, toCsv(columns, rows), 'text/csv')}
            >
              CSV
            </button>
            <button
              type="button"
              onClick={() => download(`${result.fileName}${table ? `_${table.label}` : ''}.json`, toJson(rows), 'application/json')}
            >
              JSON
            </button>
          </div>

          {builderOpen && <QueryBuilder columns={columns} rows={rows} value={search} onChange={setSearch} />}

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

          {!!result.warnings?.length && (
            <details className="warnings">
              <summary>
                {result.warnings.length} warning{result.warnings.length > 1 ? 's' : ''} about this artifact
              </summary>
              <ul>
                {result.warnings.map((w, i) => (
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
              // A parser that stopped early says so in a warning. Surface that
              // in the footer too, so completeness is never implied over a
              // truncated artifact.
              partial={result.warnings?.some((w) => /partial|cap |cancelled|truncat/i.test(w.message))}
              onSelect={setRow}
              onContext={(r, x, y) => setMenu({ row: r, x, y })}
              focus={focusRow}
              marked={marked}
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
                    onSizes((s) =>
                      position === 'bottom' ? { ...s, bottom: DEFAULT_DETAIL_SIZES.bottom } : { ...s, side: DEFAULT_DETAIL_SIZES.side },
                    )
                  }
                />
                <Detail columns={columns} row={row} position={position} size={detailSize} onClose={() => setRow(null)} />
              </>
            )}
          </div>

          {menu && (
            <div className="row-menu" role="menu" style={{ left: menu.x, top: menu.y }} onClick={(e) => e.stopPropagation()}>
              {onAddToTimeline && (
                <button
                  type="button"
                  role="menuitem"
                  onClick={() => {
                    onAddToTimeline(menu.row, columns, table?.label ?? null, result.rows?.indexOf(menu.row) ?? -1);
                    setMenu(null);
                  }}
                >
                  {marked.has(menu.row) ? 'Add to timeline again…' : 'Add to timeline…'}
                </button>
              )}
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setRow(menu.row);
                  setMenu(null);
                }}
              >
                Show details
              </button>
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  navigator.clipboard?.writeText(toJson([menu.row])).catch(() => undefined);
                  setMenu(null);
                }}
              >
                Copy row as JSON
              </button>
            </div>
          )}
        </>
      )}
    </>
  );
}
