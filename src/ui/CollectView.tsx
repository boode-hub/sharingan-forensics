import { useEffect, useMemo, useRef, useState, type ChangeEvent } from 'react';
import type { ParserInfo } from '../worker';
import type { Incoming } from './cases';
import { casePath, caveat, dialogPath, expandBundle, findTargets, kapeCommand, type Where } from './collect';
import type { KapeBundle, KapeEntry, KapeTarget } from './kapeTargets';
import { read, write } from './storage';

interface Saved extends Where {
  dest: string;
}
const isSaved = (v: unknown): v is Saved =>
  !!v && typeof v === 'object' && ['source', 'user', 'dest'].every((k) => typeof (v as Record<string, unknown>)[k] === 'string');

const GROUPS = ['Windows', 'Browsers', 'Apps', 'Antivirus', 'Logs', 'P2P'];

/**
 * Every artifact KAPE knows where to find, with a way to pick each one. A
 * browser cannot open a file dialog at a path, so the path is put on the
 * clipboard and the dialog opened: paste it into the file name box and press
 * Enter. What Windows keeps locked gets the KAPE command line instead.
 */
export function Collect({ parsers, inCase, onPick }: { parsers: ParserInfo[]; inCase: boolean; onPick: (files: Incoming[]) => void }) {
  const [data, setData] = useState<{ targets: KapeTarget[]; bundles: KapeBundle[] } | null>(null);
  const [query, setQuery] = useState('');
  const [group, setGroup] = useState('');
  const [readHere, setReadHere] = useState(false);
  const [where, setWhere] = useState<Saved>(() => read('collectWhere', { source: '', user: '', dest: '' }, isSaved));
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  // Kept by name: KAPE takes a compound target as it is.
  const [bundles, setBundles] = useState<string[]>([]);
  const [status, setStatus] = useState('');
  const files = useRef<HTMLInputElement>(null);
  const folder = useRef<HTMLInputElement>(null);
  const picking = useRef<KapeEntry | null>(null);

  // 450 KB of targets, fetched from this site only when the panel is first shown.
  useEffect(() => {
    let live = true;
    import('./kapeTargets').then((m) => live && setData({ targets: m.KAPE_TARGETS, bundles: m.KAPE_BUNDLES }));
    return () => {
      live = false;
    };
  }, []);

  const setWhereField = (k: keyof Saved, v: string) => {
    const next = { ...where, [k]: v };
    setWhere(next);
    write('collectWhere', next);
  };

  const tools = useMemo(() => new Map(parsers.map((p) => [p.id, p.ezTool || p.name])), [parsers]);
  const readers = (reads: string[]) => [...new Set(reads.map((r) => tools.get(r) ?? r))];
  const shown = useMemo(() => (data ? findTargets(data.targets, query, group, readHere) : []), [data, query, group, readHere]);
  const covered = useMemo(() => data?.targets.filter((t) => t.entries.some((e) => e.reads.length)).length ?? 0, [data]);

  const toggle = (set: Set<string>, name: string) => {
    const next = new Set(set);
    if (!next.delete(name)) next.add(name);
    return next;
  };

  const copy = (text: string, done: string) => {
    navigator.clipboard.writeText(text).then(
      () => setStatus(done),
      () => setStatus(`Copy this by hand: ${text}`),
    );
  };

  const pick = (e: KapeEntry, asFolder: boolean) => {
    const path = dialogPath(e, where);
    picking.current = e;
    copy(path, `${path} is on the clipboard: paste it into the dialog's file name box and press Enter.`);
    (asFolder ? folder : files).current?.click();
  };

  const onChosen = (ev: ChangeEvent<HTMLInputElement>) => {
    const e = picking.current;
    const list = [...(ev.target.files ?? [])];
    ev.target.value = '';
    if (!e || !list.length) return;
    onPick(list.map((file) => ({ file, path: casePath(e, where, file.webkitRelativePath || file.name) })));
    setStatus(`${list.length} file${list.length === 1 ? '' : 's'} added ${inCase ? 'to the case' : 'to this session'}.`);
  };

  const inBundle = useMemo(() => new Set(data ? bundles.flatMap((b) => expandBundle(b, data.bundles)) : []), [data, bundles]);
  const kape = [...bundles, ...[...chosen].filter((n) => !inBundle.has(n))];
  const kapeCount = new Set([...inBundle, ...chosen]).size;

  return (
    <div className="collect-page">
      <div className="toolbar">
        <strong className="tl-title">Collect</strong>
        <input className="search" placeholder="Search artifacts, paths and file names" value={query} onChange={(e) => setQuery(e.target.value)} autoFocus />
        <select value={group} onChange={(e) => setGroup(e.target.value)} aria-label="Group">
          <option value="">All groups</option>
          {GROUPS.map((g) => (
            <option key={g}>{g}</option>
          ))}
        </select>
        <label className="check">
          <input type="checkbox" checked={readHere} onChange={(e) => setReadHere(e.target.checked)} /> Read here only
        </label>
        <input
          className="where"
          placeholder="Source: this computer"
          title="Blank for this computer, or the root of a mounted image or KAPE output, e.g. E:\"
          value={where.source}
          onChange={(e) => setWhereField('source', e.target.value)}
        />
        <input
          className="where"
          placeholder="User: signed-in"
          title="The profile folder under Users. Blank on this computer means whoever is signed in"
          value={where.user}
          onChange={(e) => setWhereField('user', e.target.value)}
        />
        <span className="spacer" />
        <span className="stat">
          {data ? `${shown.length} of ${data.targets.length} · ${covered} read here` : 'Loading KAPE targets…'}
        </span>
      </div>

      {status && (
        <p className="collect-status" role="status">
          {status}
        </p>
      )}

      <div className="collect-list">
        {shown.map((t) => {
          const isOpen = open.has(t.name) || (!!query && shown.length <= 5);
          const who = readers(t.entries.flatMap((e) => e.reads));
          return (
            <section key={t.name} className={`ct${isOpen ? ' open' : ''}`}>
              <div className="ct-head">
                <input
                  type="checkbox"
                  aria-label={`Add ${t.name} to the KAPE command`}
                  title={!t.kape ? 'KAPE has no target for this' : inBundle.has(t.name) ? 'In a chosen bundle' : 'Add to the KAPE command'}
                  disabled={!t.kape || inBundle.has(t.name)}
                  checked={chosen.has(t.name) || inBundle.has(t.name)}
                  onChange={() => setChosen((s) => toggle(s, t.name))}
                />
                <button type="button" className="ct-name" aria-expanded={isOpen} onClick={() => setOpen((s) => toggle(s, t.name))}>
                  {t.name}
                </button>
                <span className="ct-group">{t.group}</span>
                <span className="ct-desc">{t.description}</span>
                {who.length ? who.map((w) => <span key={w} className="reader">{w}</span>) : <span className="reader none">not parsed here</span>}
              </div>
              {isOpen && (
                <div className="ct-body">
                  {t.includes.length > 0 && <p className="ct-inc">Also takes: {t.includes.join(', ')}</p>}
                  {t.entries.map((e, i) => {
                    const why = caveat(e);
                    return (
                      <div key={i} className="ce">
                        <div className="ce-what">
                          <span className="ce-name">{e.name}</span>
                          <code title="Where KAPE looks">
                            {e.path}
                            {e.mask ?? ''}
                            {e.recursive ? '  (and folders below)' : ''}
                          </code>
                          {why && <span className="caveat">{why}</span>}
                        </div>
                        {e.reads.length > 0 && <span className="reader">{readers(e.reads).join(', ')}</span>}
                        <button type="button" onClick={() => pick(e, false)}>
                          Files…
                        </button>
                        <button type="button" onClick={() => pick(e, true)}>
                          Folder…
                        </button>
                      </div>
                    );
                  })}
                </div>
              )}
            </section>
          );
        })}
      </div>

      <div className="toolbar collect-foot">
        <select
          value=""
          aria-label="KAPE bundle"
          onChange={(e) => e.target.value && !bundles.includes(e.target.value) && setBundles([...bundles, e.target.value])}
        >
          <option value="">Add a KAPE bundle…</option>
          {data?.bundles.map((b) => (
            <option key={b.name} value={b.name} title={b.description}>
              {b.name}
            </option>
          ))}
        </select>
        <span className="stat">
          {kapeCount} target{kapeCount === 1 ? '' : 's'} for KAPE{bundles.length ? ` (${bundles.join(', ')})` : ''}
        </span>
        <button
          type="button"
          disabled={!kape.length}
          onClick={() => {
            setChosen(new Set());
            setBundles([]);
          }}
        >
          Clear
        </button>
        <input className="where" placeholder="Destination: X:\KAPE" value={where.dest} onChange={(e) => setWhereField('dest', e.target.value)} />
        <span className="spacer" />
        <button
          type="button"
          className="primary"
          disabled={!kape.length}
          onClick={() => copy(kapeCommand(kape, where.source, where.dest), `KAPE command copied. Run it as administrator; it keeps each drive's files under a folder named for the drive, so pick from them with Source set to ${where.dest.trim().replace(/[\\/]+$/, '') || 'X:\\KAPE'}\\${(where.source.trim() || 'C')[0].toUpperCase()}.`)}
        >
          Copy KAPE command
        </button>
      </div>

      <input ref={files} type="file" multiple hidden onChange={onChosen} />
      <input ref={folder} type="file" multiple hidden {...{ webkitdirectory: '' }} onChange={onChosen} />
    </div>
  );
}
