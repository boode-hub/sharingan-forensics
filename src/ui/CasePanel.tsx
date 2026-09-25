import { useState } from 'react';
import { newCase, type CaseInfo } from './cases';
import { bytes } from './format';

type Fields = Pick<CaseInfo, 'name' | 'customer' | 'reference' | 'examiner' | 'notes'>;
const EMPTY: Fields = { name: '', customer: '', reference: '', examiner: '', notes: '' };

/**
 * Chooses the case being worked on, and creates, edits or deletes cases. With
 * no case chosen the page works as before: files are read for this session
 * only and nothing is kept.
 */
export function CasePanel({
  supported,
  cases,
  active,
  artifactCount,
  storedBytes,
  storage,
  onSelect,
  onSave,
  onDelete,
}: {
  supported: boolean;
  cases: CaseInfo[];
  active: CaseInfo | null;
  artifactCount: number;
  storedBytes: number;
  storage: { used: number; quota: number; persisted: boolean } | null;
  onSelect: (id: string | null) => void;
  onSave: (info: CaseInfo) => void;
  onDelete: (info: CaseInfo) => void;
}) {
  const [editing, setEditing] = useState<{ base: CaseInfo | null; fields: Fields } | null>(null);

  if (!supported) {
    return (
      <p className="case-note">
        This browser cannot keep files, so cases are unavailable here. Files you open are read
        for this session only.
      </p>
    );
  }

  const set = (k: keyof Fields) => (e: { target: { value: string } }) =>
    setEditing((ed) => ed && { ...ed, fields: { ...ed.fields, [k]: e.target.value } });

  if (editing) {
    const { base, fields } = editing;
    return (
      <form
        className="case-form"
        onSubmit={(e) => {
          e.preventDefault();
          if (!fields.name.trim()) return;
          onSave(base ? { ...base, ...fields } : newCase(fields));
          setEditing(null);
        }}
      >
        <strong>{base ? 'Edit case' : 'New case'}</strong>
        <label>
          Case name
          <input autoFocus required value={fields.name} onChange={set('name')} />
        </label>
        <label>
          Customer
          <input value={fields.customer} onChange={set('customer')} />
        </label>
        <label>
          Reference
          <input value={fields.reference} onChange={set('reference')} placeholder="ticket or case number" />
        </label>
        <label>
          Examiner
          <input value={fields.examiner} onChange={set('examiner')} />
        </label>
        <label>
          Notes
          <textarea rows={3} value={fields.notes} onChange={set('notes')} />
        </label>
        <div className="case-actions">
          <button type="submit" className="primary" disabled={!fields.name.trim()}>
            Save
          </button>
          <button type="button" onClick={() => setEditing(null)}>
            Cancel
          </button>
        </div>
      </form>
    );
  }

  return (
    <div className="case-panel">
      <div className="case-row">
        <select
          value={active?.id ?? ''}
          onChange={(e) => onSelect(e.target.value || null)}
          aria-label="Case"
        >
          <option value="">No case — this session only</option>
          {cases.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}
              {c.customer ? ` · ${c.customer}` : ''}
            </option>
          ))}
        </select>
        <button type="button" onClick={() => setEditing({ base: null, fields: EMPTY })} title="New case">
          + Case
        </button>
      </div>
      {active && (
        <div className="case-card">
          <div className="case-title">{active.name}</div>
          {(active.customer || active.reference) && (
            <div className="case-sub">
              {[active.customer, active.reference].filter(Boolean).join(' · ')}
            </div>
          )}
          {active.examiner && <div className="case-sub">Examiner: {active.examiner}</div>}
          {active.notes && <div className="case-notes">{active.notes}</div>}
          <div className="case-sub">
            {artifactCount.toLocaleString()} artifact{artifactCount === 1 ? '' : 's'} ·{' '}
            {bytes(storedBytes)} stored in this browser
          </div>
          <div className="case-actions">
            <button
              type="button"
              onClick={() =>
                setEditing({
                  base: active,
                  fields: {
                    name: active.name,
                    customer: active.customer,
                    reference: active.reference,
                    examiner: active.examiner,
                    notes: active.notes,
                  },
                })
              }
            >
              Edit
            </button>
            <button type="button" className="danger" onClick={() => onDelete(active)}>
              Delete case
            </button>
          </div>
        </div>
      )}
      {storage && storage.quota > 0 && (
        <div className="case-storage" title="All cases together, in this browser">
          Browser storage {bytes(storage.used)} of {bytes(storage.quota)}
          {storage.persisted ? '' : ' · may be cleared by the browser if the disk fills'}
        </div>
      )}
    </div>
  );
}
