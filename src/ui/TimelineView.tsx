import { useMemo, useState } from 'react';
import type { Column, Row } from '../core/types';
import { download, fmt } from './format';
import {
  gap,
  guessLane,
  snapshot,
  sortEvents,
  summarise,
  TAGS,
  timeFields,
  timelineCsv,
  timelineReport,
  type ReportInfo,
  type Timeline,
  type TimelineEvent,
  type TimelineSource,
} from './timeline';

/** What the row menu hands over when an event is added. */
export interface Pending {
  row: Row;
  columns: Column[];
  source: TimelineSource;
}

/**
 * Adding a row to the timeline: which of its times, which lane, a label, a
 * tag and a note, each filled in with a guess the examiner can change.
 */
export function AddEventDialog({
  pending,
  timeline,
  lastLane,
  onAdd,
  onCancel,
}: {
  pending: Pending;
  timeline: Timeline;
  lastLane: string | null;
  onAdd: (e: TimelineEvent) => void;
  onCancel: () => void;
}) {
  const times = timeFields(pending.columns, pending.row);
  const [timeField, setTimeField] = useState(times[0]?.key ?? '');
  const initialTime = (key: string) => {
    const v = pending.row[key];
    return v instanceof Date ? v.toISOString() : '';
  };
  const [time, setTime] = useState(initialTime(times[0]?.key ?? ''));
  const [lane, setLane] = useState(() => guessLane(pending.row, timeline.lanes, lastLane));
  const [label, setLabel] = useState(() => summarise(pending.row, pending.columns));
  const [tag, setTag] = useState('');
  const [note, setNote] = useState('');
  const timeOk = time === '' || !Number.isNaN(Date.parse(time));

  const add = () => {
    if (!timeOk || !lane.trim()) return;
    const field = pending.columns.find((c) => c.key === timeField);
    const fieldTime = field ? initialTime(field.key) : '';
    onAdd({
      id: crypto.randomUUID(),
      time: time ? new Date(time).toISOString() : null,
      // A time typed over the column's is the examiner's, not the column's.
      timeField: field && time === fieldTime ? field.label : time ? 'entered by examiner' : null,
      lane: lane.trim(),
      label: label.trim() || '(no label)',
      tag: tag.trim(),
      note: note.trim(),
      source: pending.source,
      data: snapshot(pending.row, pending.columns),
      added: new Date().toISOString(),
    });
  };

  return (
    <div className="modal-backdrop" onMouseDown={onCancel}>
      <form
        className="modal event-dialog"
        role="dialog"
        aria-label="Add to timeline"
        onMouseDown={(e) => e.stopPropagation()}
        onSubmit={(e) => {
          e.preventDefault();
          add();
        }}
        onKeyDown={(e) => e.key === 'Escape' && onCancel()}
      >
        <h2>Add to timeline</h2>
        <p className="from">
          {pending.source.path || pending.source.fileName} · {pending.source.parser}
          {pending.source.table ? ` · ${pending.source.table}` : ''} · row {pending.source.rowIndex + 1}
        </p>
        <label>
          Time (UTC)
          <span className="row2">
            {times.length > 0 && (
              <select
                value={timeField}
                onChange={(e) => {
                  setTimeField(e.target.value);
                  setTime(initialTime(e.target.value));
                }}
                aria-label="Which time"
              >
                {times.map((c) => (
                  <option key={c.key} value={c.key}>
                    {c.label}
                  </option>
                ))}
              </select>
            )}
            <input
              value={time}
              onChange={(e) => setTime(e.target.value)}
              placeholder={times.length ? '' : 'No time in this row: type one, or leave it undated'}
              aria-invalid={!timeOk}
              className={timeOk ? '' : 'bad'}
            />
          </span>
        </label>
        <label>
          Lane (host, user, or anything)
          <input list="timeline-lanes" value={lane} onChange={(e) => setLane(e.target.value)} required />
          <datalist id="timeline-lanes">
            {timeline.lanes.map((l) => (
              <option key={l} value={l} />
            ))}
          </datalist>
        </label>
        <label>
          Label
          <input value={label} onChange={(e) => setLabel(e.target.value)} autoFocus />
        </label>
        <label>
          Tag
          <input list="timeline-tags" value={tag} onChange={(e) => setTag(e.target.value)} placeholder="e.g. Execution, Persistence, Logon" />
          <datalist id="timeline-tags">
            {[...new Set([...timeline.events.map((e) => e.tag).filter(Boolean), ...TAGS])].map((t) => (
              <option key={t} value={t} />
            ))}
          </datalist>
        </label>
        <label>
          Note
          <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={3} placeholder="Why this matters" />
        </label>
        <div className="actions">
          <button type="submit" className="primary" disabled={!timeOk || !lane.trim()}>
            Add
          </button>
          <button type="button" onClick={onCancel}>
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

/** Each event with whether it starts a new day and how long after the dated one before it came. */
function withDays(events: TimelineEvent[]) {
  const out: Array<{ e: TimelineEvent; day: string; newDay: boolean; gap: string }> = [];
  let lastDay = '';
  let lastTime: string | null = null;
  for (const e of events) {
    const day = e.time ? e.time.slice(0, 10) : 'Undated';
    out.push({ e, day, newDay: day !== lastDay, gap: e.time && lastTime ? gap(lastTime, e.time) : '' });
    lastDay = day;
    if (e.time) lastTime = e.time;
  }
  return out;
}

/**
 * The timeline page: a vertical line per lane, each event a branch off its
 * lane in time order, with the gap since the one before. Selecting an event
 * shows what was recorded, lets it be edited, and opens its source row again.
 */
export function TimelineView({
  timeline,
  onChange,
  onOpenSource,
  report,
  persisted,
}: {
  timeline: Timeline;
  onChange: (t: Timeline) => void;
  onOpenSource: (e: TimelineEvent) => void;
  report: ReportInfo;
  /** Saved with a case, or only for this session. */
  persisted: boolean;
}) {
  const [query, setQuery] = useState('');
  const [tagFilter, setTagFilter] = useState('');
  const [laneFilter, setLaneFilter] = useState('');
  const [selected, setSelected] = useState<string | null>(null);

  const lanes = useMemo(() => {
    const used = new Set(timeline.events.map((e) => e.lane));
    return [...timeline.lanes.filter((l) => used.has(l)), ...[...used].filter((l) => !timeline.lanes.includes(l))];
  }, [timeline]);
  const tags = useMemo(() => [...new Set(timeline.events.map((e) => e.tag).filter(Boolean))].sort(), [timeline]);
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return sortEvents(timeline.events).filter(
      (e) =>
        (!tagFilter || e.tag === tagFilter) &&
        (!laneFilter || e.lane === laneFilter) &&
        (!q || [e.label, e.note, e.tag, e.lane, e.source.path, ...Object.values(e.data)].some((s) => s.toLowerCase().includes(q))),
    );
  }, [timeline, query, tagFilter, laneFilter]);
  const rows = useMemo(() => withDays(shown), [shown]);
  const visibleLanes = laneFilter ? [laneFilter] : lanes;
  const current = timeline.events.find((e) => e.id === selected) ?? null;

  const update = (id: string, patch: Partial<TimelineEvent>) =>
    onChange({
      lanes: patch.lane && !timeline.lanes.includes(patch.lane) ? [...timeline.lanes, patch.lane] : timeline.lanes,
      events: timeline.events.map((e) => (e.id === id ? { ...e, ...patch } : e)),
    });
  const remove = (id: string) => {
    if (!window.confirm('Remove this event from the timeline?')) return;
    onChange({ ...timeline, events: timeline.events.filter((e) => e.id !== id) });
    setSelected(null);
  };
  const stamp = new Date().toISOString().slice(0, 19).replaceAll(':', '');
  const base = `${(report.caseName || 'timeline').replace(/[^\w.-]+/g, '_')}_timeline_${stamp}`;

  return (
    <div className="timeline-page">
      <div className="toolbar">
        <strong className="tl-title">Timeline</strong>
        <input className="search" placeholder="Search events, notes and recorded fields" value={query} onChange={(e) => setQuery(e.target.value)} />
        <select value={laneFilter} onChange={(e) => setLaneFilter(e.target.value)} aria-label="Lane">
          <option value="">All lanes ({lanes.length})</option>
          {lanes.map((l) => (
            <option key={l} value={l}>
              {l}
            </option>
          ))}
        </select>
        <select value={tagFilter} onChange={(e) => setTagFilter(e.target.value)} aria-label="Tag">
          <option value="">All tags</option>
          {tags.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <span className="spacer" />
        <span className="stat">
          {shown.length} of {timeline.events.length} event{timeline.events.length === 1 ? '' : 's'}
          {persisted ? ' · saved with the case' : ' · this session only: open a case to keep it'}
        </span>
        <button type="button" disabled={!timeline.events.length} onClick={() => download(`${base}.html`, timelineReport(timeline, report), 'text/html')}>
          Report
        </button>
        <button type="button" disabled={!timeline.events.length} onClick={() => download(`${base}.csv`, timelineCsv(timeline), 'text/csv')}>
          CSV
        </button>
        <button
          type="button"
          disabled={!timeline.events.length}
          onClick={() => download(`${base}.json`, JSON.stringify({ ...report, generated: new Date().toISOString(), ...timeline }, null, 2), 'application/json')}
        >
          JSON
        </button>
      </div>

      <div className="tl-body">
        {timeline.events.length === 0 ? (
          <div className="empty">
            <p>
              No events yet. Right-click a row in any artifact and choose <strong>Add to timeline</strong>; each event
              lands on a lane (a host, a user) in time order, and can be opened again from here.
            </p>
          </div>
        ) : (
          <div className="tl-scroll">
            <div className="tl-lanes" style={{ gridTemplateColumns: `140px repeat(${visibleLanes.length}, minmax(220px, 1fr))` }}>
              <div className="tl-head when">Time (UTC)</div>
              {visibleLanes.map((l) => (
                <div key={l} className="tl-head lane-name" title={l}>
                  {l}
                </div>
              ))}
              {rows.map(({ e, day, newDay, gap: g }) => {
                return [
                  newDay && (
                    <div key={`d-${e.id}`} className="tl-day" style={{ gridColumn: `1 / span ${visibleLanes.length + 1}` }}>
                      {day}
                    </div>
                  ),
                  <div key={`t-${e.id}`} className="tl-time">
                    {e.time ? e.time.slice(11, 23) : '—'}
                    {g && <span className="gap">{g}</span>}
                  </div>,
                  ...visibleLanes.map((l) =>
                    l === e.lane ? (
                      <div key={`${e.id}-${l}`} className="tl-cell has">
                        <button type="button" className={`tl-card${selected === e.id ? ' on' : ''}`} onClick={() => setSelected(e.id)}>
                          <span className="tl-top">
                            {e.tag && <span className="tag">{e.tag}</span>}
                            <span className="src">{e.source.fileName}</span>
                          </span>
                          <span className="tl-label">{e.label}</span>
                          {e.note && <span className="tl-note">{e.note}</span>}
                        </button>
                      </div>
                    ) : (
                      <div key={`${e.id}-${l}`} className="tl-cell" />
                    ),
                  ),
                ];
              })}
            </div>
          </div>
        )}

        {current && (
          <aside className="tl-detail" aria-label="Selected event">
            <div className="tl-detail-head">
              <strong>Event</strong>
              <button type="button" className="pane-close" aria-label="Close" onClick={() => setSelected(null)}>
                ×
              </button>
            </div>
            <label>
              Time (UTC)
              <input
                defaultValue={current.time ?? ''}
                key={`time-${current.id}-${current.time}`}
                onBlur={(e) => {
                  const v = e.target.value.trim();
                  if (v === (current.time ?? '')) return;
                  if (v && Number.isNaN(Date.parse(v))) return;
                  update(current.id, { time: v ? new Date(v).toISOString() : null, timeField: v ? 'entered by examiner' : null });
                }}
              />
            </label>
            <label>
              Lane
              <input list="timeline-lanes-edit" defaultValue={current.lane} key={`lane-${current.id}`} onBlur={(e) => e.target.value.trim() && update(current.id, { lane: e.target.value.trim() })} />
              <datalist id="timeline-lanes-edit">
                {lanes.map((l) => (
                  <option key={l} value={l} />
                ))}
              </datalist>
            </label>
            <label>
              Label
              <input defaultValue={current.label} key={`label-${current.id}`} onBlur={(e) => update(current.id, { label: e.target.value.trim() || current.label })} />
            </label>
            <label>
              Tag
              <input list="timeline-tags-edit" defaultValue={current.tag} key={`tag-${current.id}`} onBlur={(e) => update(current.id, { tag: e.target.value.trim() })} />
              <datalist id="timeline-tags-edit">
                {TAGS.map((t) => (
                  <option key={t} value={t} />
                ))}
              </datalist>
            </label>
            <label>
              Note
              <textarea defaultValue={current.note} key={`note-${current.id}`} rows={4} onBlur={(e) => update(current.id, { note: e.target.value })} />
            </label>
            <p className="from">
              From {current.source.path || current.source.fileName} · {current.source.parser}
              {current.source.table ? ` · ${current.source.table}` : ''} · row {current.source.rowIndex + 1}
              {current.timeField ? ` · time from ${current.timeField}` : ''}
            </p>
            <div className="actions">
              <button type="button" className="primary" onClick={() => onOpenSource(current)}>
                Open the source row
              </button>
              <button type="button" onClick={() => remove(current.id)}>
                Remove
              </button>
            </div>
            <table className="tl-fields">
              <tbody>
                {Object.entries(current.data).map(([k, v]) => (
                  <tr key={k}>
                    <th>{k}</th>
                    <td>{fmt(v)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </aside>
        )}
      </div>
    </div>
  );
}
