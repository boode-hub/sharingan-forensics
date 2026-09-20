import { useCallback, useEffect, useRef, useState } from 'react';
import type { Row } from './core/types';
import { Grid } from './ui/Grid';
import { bytes, download, fmt, toCsv, toJson } from './ui/format';
import type { WorkRequest, WorkResult } from './worker';

let nextId = 1;

export default function App() {
  const [results, setResults] = useState<WorkResult[]>([]);
  const [sel, setSel] = useState<number | null>(null);
  const [row, setRow] = useState<Row | null>(null);
  const [filter, setFilter] = useState('');
  const [busy, setBusy] = useState(0);
  const [bigFiles, setBigFiles] = useState<string[]>([]);
  const [dragging, setDragging] = useState(false);
  const worker = useRef<Worker>(null);

  useEffect(() => {
    const w = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' });
    w.onmessage = (e: MessageEvent<WorkResult>) => {
      setResults((rs) => [...rs, e.data]);
      setBusy((n) => n - 1);
      setSel((s) => s ?? e.data.id);
    };
    worker.current = w;
    return () => w.terminate();
  }, []);

  const ingest = useCallback((files: FileList | File[]) => {
    for (const file of files) {
      setBusy((n) => n + 1);
      // Everything in the file is parsed regardless of size — nothing is
      // truncated. But past this point it takes long enough that silence looks
      // like a hang, so say so rather than leave the analyst guessing.
      if (file.size >= 64 * 1024 * 1024) {
        setBigFiles((b) => [...b, `${file.name} (${bytes(file.size)})`]);
      }
      worker.current?.postMessage({ id: nextId++, file } satisfies WorkRequest);
    }
  }, []);

  const current = results.find((r) => r.id === sel);

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
      <header>
        <h1>
          Sharingan <span>Forensics</span>
        </h1>
        <p className="privacy">
          Every byte is parsed in this tab. Nothing is uploaded, and there is no server to upload
          to.
        </p>
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
              Large file — this may take a while, and the whole file is still
              parsed: {bigFiles.join(', ')}
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
                    setFilter('');
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
              Drop a <code>$I</code>, <code>.pf</code>, <code>.lnk</code> or <code>.evtx</code> file
              anywhere on this page.
            </p>
          )}
        </aside>

        <main>
          {!current && <div className="empty">No artifact selected.</div>}

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
                  className="filter"
                  placeholder="Filter rows…"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                />
                <span className="spacer" />
                <span className="stat">
                  {current.parser.name} · {bytes(current.fileSize)} · {current.ms} ms
                </span>
                <button
                  type="button"
                  onClick={() =>
                    download(
                      `${current.fileName}.csv`,
                      toCsv(current.parser!.columns, current.rows!),
                      'text/csv',
                    )
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

              {!!current.warnings?.length && (
                <details className="warnings">
                  <summary>
                    {current.warnings.length} warning{current.warnings.length > 1 ? 's' : ''} — the
                    rows below are what could be recovered
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

              <Grid
                columns={current.parser.columns}
                rows={current.rows}
                filter={filter}
                onSelect={setRow}
              />

              {row && (
                <div className="detail">
                  <table>
                    <tbody>
                      {current.parser.columns.map((c) => (
                        <tr key={c.key}>
                          <th>{c.label}</th>
                          <td>{fmt(row[c.key])}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
