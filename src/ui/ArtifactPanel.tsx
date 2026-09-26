import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { bytes } from './format';
import {
  buildTree,
  CATEGORIES,
  categoryOf,
  entryFilter,
  folderPaths,
  fuzzyScore,
  OTHER,
  sortEntries,
  UNRECOGNISED,
  type Entry,
  type SortKey,
  type TreeNode,
} from './navigator';
import { read, write } from './storage';

type View = 'tree' | 'category' | 'list';
const isView = (v: unknown): v is View => v === 'tree' || v === 'category' || v === 'list';
const isSort = (v: unknown): v is SortKey => v === 'path' || v === 'name' || v === 'size' || v === 'type';

/**
 * The artifacts of a case (or of this session), to find and open: a filter,
 * a category menu, a folder tree or grouped or flat list, keyboard movement,
 * and a quick switcher (Ctrl+K). Each entry opens in the active pane, or
 * beside it with the split button or Ctrl-click.
 */
export function ArtifactPanel({
  entries,
  panesOf,
  activeKey,
  describe,
  onOpen,
  onRemove,
}: {
  entries: Entry[];
  /** Which panes show an entry: "L", "R" or both. */
  panesOf: (key: string) => string;
  /** The entry in the active pane, for Alt+Up / Alt+Down. */
  activeKey: string | null;
  describe: (e: Entry) => ReactNode;
  onOpen: (e: Entry, beside: boolean) => void;
  onRemove?: (e: Entry) => void;
}) {
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('');
  const [view, setView] = useState<View>(() => read('navView', 'tree', isView));
  const [sort, setSort] = useState<SortKey>(() => read('navSort', 'path', isSort));
  const [openedOnly, setOpenedOnly] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  // Top-level folders start open (a KAPE collection is one "C"); these are the ones closed since.
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [switcher, setSwitcher] = useState(false);
  const filterBox = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLDivElement>(null);

  useEffect(() => void write('navView', view), [view]);
  useEffect(() => void write('navSort', sort), [sort]);

  const counts = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of entries) {
      const c = categoryOf(e.kind).id;
      m.set(c, (m.get(c) ?? 0) + 1);
    }
    return m;
  }, [entries]);
  const categories = [...CATEGORIES, OTHER, UNRECOGNISED].filter((c) => counts.has(c.id));

  const shown = useMemo(() => {
    const test = entryFilter(query);
    return sortEntries(
      entries.filter((e) => (!category || categoryOf(e.kind).id === category) && (!openedOnly || e.opened) && test(e)),
      sort,
    );
  }, [entries, query, category, openedOnly, sort]);

  const tree = useMemo(() => (view === 'tree' ? buildTree(shown) : null), [view, shown]);
  // While filtering, every folder with a match is open, so matches are never hidden.
  const narrowed = query.trim() !== '' || category !== '' || openedOnly;
  const topLevel = useMemo(() => new Set(tree?.folders.map((f) => f.path)), [tree]);
  const isOpen = (path: string) => narrowed || (topLevel.has(path) ? !collapsed.has(path) : expanded.has(path));
  const flip = (set: typeof setExpanded, path: string) =>
    set((s) => {
      const n = new Set(s);
      if (n.has(path)) n.delete(path);
      else n.add(path);
      return n;
    });
  const toggle = (path: string) => flip(topLevel.has(path) ? setCollapsed : setExpanded, path);

  // Keys: / to filter, Ctrl+K to jump, Alt+Up / Alt+Down for the previous or next artifact.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = e.target instanceof HTMLElement && e.target.closest('input, textarea, select, [contenteditable]');
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setSwitcher(true);
      } else if (e.key === '/' && !typing) {
        e.preventDefault();
        filterBox.current?.focus();
      } else if (e.altKey && (e.key === 'ArrowDown' || e.key === 'ArrowUp') && shown.length > 0) {
        e.preventDefault();
        const i = shown.findIndex((x) => x.key === activeKey);
        const next = e.key === 'ArrowDown' ? (i + 1) % shown.length : (i - 1 + shown.length) % shown.length;
        onOpen(shown[i < 0 ? 0 : next], false);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [shown, activeKey, onOpen]);

  /** Up and Down move between the entries and folders showing; Enter opens (with Ctrl or Shift, beside). */
  const onListKey = (e: React.KeyboardEvent) => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    const items = [...(list.current?.querySelectorAll<HTMLElement>('[data-nav]') ?? [])];
    const i = items.indexOf(document.activeElement as HTMLElement);
    const next = items[e.key === 'ArrowDown' ? Math.min(items.length - 1, i + 1) : Math.max(0, i - 1)];
    if (next) {
      e.preventDefault();
      next.focus();
    }
  };

  const item = (e: Entry, showDir: boolean) => {
    const panes = panesOf(e.key);
    return (
      <li key={e.key} className="artifact">
        <button
          type="button"
          data-nav
          className={panes ? 'on' : ''}
          title={`${e.path}\nClick to open · Ctrl+click to open beside`}
          onClick={(ev) => onOpen(e, ev.ctrlKey || ev.metaKey || ev.shiftKey)}
        >
          <span className="fn">
            {e.name}
            {panes && <span className="panes-badge">{panes}</span>}
          </span>
          {showDir && e.dir && <span className="dir">{e.dir}</span>}
          <span className="meta">{describe(e)}</span>
        </button>
        <button
          type="button"
          className="beside"
          aria-label={`Open ${e.name} beside`}
          title="Open beside (split view)"
          onClick={() => onOpen(e, true)}
        >
          ⧉
        </button>
        {onRemove && (
          <button
            type="button"
            className="remove"
            aria-label={`Remove ${e.path} from the case`}
            title="Remove from the case"
            onClick={() => onRemove(e)}
          >
            ×
          </button>
        )}
      </li>
    );
  };

  const folder = (n: TreeNode, depth: number): ReactNode => (
    <li key={n.path} className="folder">
      <button
        type="button"
        data-nav
        className="folder-row"
        style={{ paddingLeft: 6 + depth * 12 }}
        aria-expanded={isOpen(n.path)}
        onClick={() => toggle(n.path)}
        title={n.path}
      >
        <span className="caret">{isOpen(n.path) ? '▾' : '▸'}</span>
        <span className="folder-name">{n.name}</span>
        <span className="count">{n.count.toLocaleString()}</span>
      </button>
      {isOpen(n.path) && (
        <ul className="files nested" style={{ paddingLeft: depth * 12 + 10 }}>
          {n.folders.map((f) => folder(f, depth + 1))}
          {n.entries.map((e) => item(e, false))}
        </ul>
      )}
    </li>
  );

  const grouped = useMemo(() => {
    if (view !== 'category') return [];
    const groups = new Map<string, Entry[]>();
    for (const e of shown) {
      const c = categoryOf(e.kind).label;
      groups.set(c, [...(groups.get(c) ?? []), e]);
    }
    const order = [...CATEGORIES, OTHER, UNRECOGNISED].map((c) => c.label);
    return [...groups].sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0]));
  }, [view, shown]);

  if (entries.length === 0) return null;

  return (
    <div className="navigator" ref={list} onKeyDown={onListKey}>
      <div className="nav-filter">
        <input
          ref={filterBox}
          type="search"
          placeholder="Filter: name, ext:evtx, in:Prefetch, type:registry, size>10mb"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') setQuery('');
            if (e.key === 'ArrowDown') {
              e.preventDefault();
              list.current?.querySelector<HTMLElement>('[data-nav]')?.focus();
            }
          }}
          aria-label="Filter artifacts"
          title="Words are combined: ext:pf in:Windows -chrome · type:event · size>10mb · &quot;a phrase&quot; · / to focus · Ctrl+K to jump"
        />
      </div>
      <div className="nav-controls">
        <select value={category} onChange={(e) => setCategory(e.target.value)} aria-label="Category">
          <option value="">All artifacts ({entries.length.toLocaleString()})</option>
          {categories.map((c) => (
            <option key={c.id} value={c.id}>
              {c.label} ({counts.get(c.id)?.toLocaleString()})
            </option>
          ))}
        </select>
        <div className="segmented" role="radiogroup" aria-label="Show as">
          {(
            [
              ['tree', 'Folders'],
              ['category', 'Types'],
              ['list', 'List'],
            ] as const
          ).map(([v, label]) => (
            <button key={v} type="button" role="radio" aria-checked={view === v} className={view === v ? 'on' : ''} onClick={() => setView(v)}>
              {label}
            </button>
          ))}
        </div>
      </div>
      <div className="nav-controls">
        <select value={sort} onChange={(e) => setSort(e.target.value as SortKey)} aria-label="Sort by">
          <option value="path">Sort: path</option>
          <option value="name">Sort: name</option>
          <option value="size">Sort: size</option>
          <option value="type">Sort: type</option>
        </select>
        <label className="check">
          <input type="checkbox" checked={openedOnly} onChange={(e) => setOpenedOnly(e.target.checked)} /> Opened
        </label>
        {view === 'tree' && tree && (
          <span className="tree-actions">
            <button
              type="button"
              title="Expand every folder"
              onClick={() => {
                setExpanded(new Set(folderPaths(tree)));
                setCollapsed(new Set());
              }}
            >
              +
            </button>
            <button
              type="button"
              title="Collapse every folder"
              onClick={() => {
                setExpanded(new Set());
                setCollapsed(new Set(topLevel));
              }}
            >
              −
            </button>
          </span>
        )}
      </div>
      <p className="nav-count">
        {shown.length === entries.length
          ? `${entries.length.toLocaleString()} artifact${entries.length === 1 ? '' : 's'}, ${bytes(entries.reduce((n, e) => n + e.size, 0))}`
          : `${shown.length.toLocaleString()} of ${entries.length.toLocaleString()} shown`}
        <button type="button" className="link" onClick={() => setSwitcher(true)} title="Jump to any artifact by typing part of its path">
          Ctrl+K
        </button>
      </p>

      {view === 'tree' && tree && (
        <ul className="files">
          {tree.folders.map((f) => folder(f, 0))}
          {tree.entries.map((e) => item(e, false))}
        </ul>
      )}
      {view === 'category' &&
        grouped.map(([label, list]) => (
          <details key={label} className="group" open>
            <summary>
              {label} <span className="count">{list.length.toLocaleString()}</span>
            </summary>
            <ul className="files">{list.map((e) => item(e, true))}</ul>
          </details>
        ))}
      {view === 'list' && <ul className="files">{shown.map((e) => item(e, true))}</ul>}
      {shown.length === 0 && <p className="hint">Nothing matches the filter.</p>}

      {switcher && <QuickSwitcher entries={entries} onOpen={onOpen} onClose={() => setSwitcher(false)} />}
    </div>
  );
}

/** Ctrl+K: type any part of a path, Enter to open, Shift+Enter to open beside. */
function QuickSwitcher({ entries, onOpen, onClose }: { entries: Entry[]; onOpen: (e: Entry, beside: boolean) => void; onClose: () => void }) {
  const [q, setQ] = useState('');
  const [at, setAt] = useState(0);
  const matches = useMemo(() => {
    const scored = entries
      .map((e) => ({ e, s: fuzzyScore(q, e.path) }))
      .filter((x): x is { e: Entry; s: number } => x.s !== null);
    // Opened artifacts first when nothing is typed: jumping back is the common case.
    scored.sort((a, b) => (q ? b.s - a.s : Number(b.e.opened) - Number(a.e.opened) || a.e.path.localeCompare(b.e.path)));
    return scored.slice(0, 60).map((x) => x.e);
  }, [entries, q]);
  const pick = (e: Entry | undefined, beside: boolean) => {
    if (!e) return;
    onOpen(e, beside);
    onClose();
  };
  return (
    <div className="switcher-backdrop" onMouseDown={onClose}>
      <div className="switcher" role="dialog" aria-label="Jump to an artifact" onMouseDown={(e) => e.stopPropagation()}>
        <input
          autoFocus
          placeholder="Jump to… (Enter opens, Shift+Enter opens beside, Esc closes)"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setAt(0);
          }}
          onKeyDown={(e) => {
            if (e.key === 'Escape') onClose();
            else if (e.key === 'ArrowDown') {
              e.preventDefault();
              setAt((i) => Math.min(matches.length - 1, i + 1));
            } else if (e.key === 'ArrowUp') {
              e.preventDefault();
              setAt((i) => Math.max(0, i - 1));
            } else if (e.key === 'Enter') pick(matches[at], e.shiftKey || e.ctrlKey || e.metaKey);
          }}
          aria-label="Artifact to jump to"
        />
        <ul>
          {matches.map((e, i) => (
            <li key={e.key}>
              <button
                type="button"
                className={i === at ? 'on' : ''}
                onMouseEnter={() => setAt(i)}
                onClick={(ev) => pick(e, ev.shiftKey || ev.ctrlKey || ev.metaKey)}
              >
                <span className="fn">{e.name}</span>
                <span className="dir">{e.dir}</span>
                <span className="kind">{e.kindName || 'unrecognised'}</span>
              </button>
            </li>
          ))}
          {matches.length === 0 && <li className="none">No artifact matches.</li>}
        </ul>
      </div>
    </div>
  );
}
