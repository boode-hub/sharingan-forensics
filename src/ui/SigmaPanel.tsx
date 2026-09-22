import { useRef } from 'react';
import type { SigmaRule } from './sigma';

const EXAMPLE = `title: RDP login from localhost
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 10
    IpAddress:
      - '::1'
      - '127.0.0.1'
  condition: selection
level: high`;

/**
 * Where a Sigma rule is pasted, run and explained. The rule's matches become a
 * filter on the grid, alongside the search and the column filters.
 */
export function SigmaPanel({
  text,
  onText,
  onRun,
  onClear,
  onClose,
  rule,
  error,
  working,
  matched,
  total,
}: {
  text: string;
  onText: (t: string) => void;
  onRun: () => void;
  onClear: () => void;
  onClose: () => void;
  rule: SigmaRule | null;
  error: string | null;
  working: boolean;
  /** Rows the rule matches in this artifact, before any other filter. */
  matched: number;
  total: number;
}) {
  const fileRef = useRef<HTMLInputElement>(null);

  return (
    <section className="sigma" aria-label="Sigma rule">
      <div className="sigma-edit">
        <textarea
          value={text}
          onChange={(e) => onText(e.target.value)}
          placeholder={`Paste a Sigma rule here, or open a .yml file.\n\n${EXAMPLE}`}
          spellCheck={false}
          aria-label="Sigma rule"
          onKeyDown={(e) => {
            if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
              e.preventDefault();
              onRun();
            }
          }}
        />
        <div className="sigma-actions">
          <button type="button" className="primary" onClick={onRun} disabled={!text.trim() || working}>
            {working ? 'Compiling…' : 'Run rule'}
          </button>
          <button type="button" onClick={() => fileRef.current?.click()}>
            Open .yml…
          </button>
          <input
            ref={fileRef}
            type="file"
            accept=".yml,.yaml,text/yaml"
            hidden
            onChange={async (e) => {
              const f = e.target.files?.[0];
              e.target.value = '';
              if (f) onText(await f.text());
            }}
          />
          {rule && (
            <button type="button" onClick={onClear}>
              Clear rule
            </button>
          )}
          <button type="button" onClick={() => onText(EXAMPLE)}>
            Example
          </button>
          <span className="spacer" />
          <button type="button" onClick={onClose} aria-label="Close the Sigma panel">
            Close
          </button>
        </div>
        <p className="sigma-hint">Ctrl+Enter runs the rule. It is evaluated here, against the rows in this tab.</p>
      </div>

      <div className="sigma-result" aria-live="polite">
        {error && <p className="sigma-error">Rule not usable — {error}</p>}
        {rule && !error && (
          <>
            <div className="sigma-title">
              {rule.level && <span className={`level level-${rule.level.toLowerCase()}`}>{rule.level}</span>}
              <strong>{rule.title}</strong>
            </div>
            <p className="sigma-count">
              Matches <strong>{matched.toLocaleString()}</strong> of {total.toLocaleString()} rows in
              this artifact
            </p>
            {rule.description && <p className="sigma-desc">{rule.description}</p>}
            <dl className="sigma-meta">
              {Object.keys(rule.logsource).length > 0 && (
                <>
                  <dt>Logsource</dt>
                  <dd>
                    {Object.entries(rule.logsource)
                      .map(([k, v]) => `${k}: ${v}`)
                      .join(' · ')}
                  </dd>
                </>
              )}
              {rule.tags.length > 0 && (
                <>
                  <dt>Tags</dt>
                  <dd>{rule.tags.join(' ')}</dd>
                </>
              )}
              {rule.id && (
                <>
                  <dt>Id</dt>
                  <dd>{rule.id}</dd>
                </>
              )}
            </dl>
            {rule.notes.length > 0 && (
              <ul className="sigma-notes">
                {rule.notes.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            )}
          </>
        )}
        {!rule && !error && (
          <p className="sigma-idle">
            No rule is running. Paste one and press <strong>Run rule</strong>; its matches filter the
            table, together with any search and column filters.
          </p>
        )}
      </div>
    </section>
  );
}
