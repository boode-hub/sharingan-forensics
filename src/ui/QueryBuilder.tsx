import { useMemo, useState } from 'react';
import type { Column, Row } from '../core/types';
import {
  addCondition,
  addNot,
  addOperator,
  BUILDER_OPS,
  closeBracket,
  condition,
  ending,
  openBracket,
  openBrackets,
  type BuilderOp,
} from './builder';
import { eventFieldNames, norm } from './fields';

/**
 * A condition at a time: pick a field, a comparison and a value, then join
 * the next one with AND or OR, and group with brackets. It writes into the
 * search box, which stays the one place the filter lives.
 */
export function QueryBuilder({
  columns,
  rows,
  value,
  onChange,
}: {
  columns: Column[];
  rows: Row[];
  value: string;
  onChange: (text: string) => void;
}) {
  const [field, setField] = useState('');
  const [op, setOp] = useState<BuilderOp>('contains');
  const [operand, setOperand] = useState('');
  // Each press remembers the text it replaced, so Undo steps back one press
  // as long as nothing was typed into the search box since.
  const [history, setHistory] = useState<Array<{ before: string; after: string }>>([]);

  // Columns first, then fields found inside the events themselves, which is
  // where TargetUserName, LogonType or CommandLine live.
  const fields = useMemo(() => {
    const known = new Set(columns.flatMap((c) => [norm(c.key), norm(c.label)]));
    return [
      ...columns.map((c) => ({ name: c.key, hint: c.label })),
      ...eventFieldNames(rows)
        .filter((n) => !known.has(norm(n)))
        .map((n) => ({ name: n, hint: 'event field' })),
    ];
  }, [columns, rows]);

  const push = (next: string) => {
    if (next === value) return;
    setHistory((h) => [...h, { before: value, after: next }]);
    onChange(next);
  };

  const add = () => {
    if (!operand) return;
    push(addCondition(value, condition(field, field ? op : 'contains', operand)));
    setOperand('');
  };

  const end = ending(value);
  const open = openBrackets(value);
  const last = history[history.length - 1];
  const canUndo = !!last && last.after === value;

  return (
    <div className="builder" role="group" aria-label="Build a filter">
      <input
        className="builder-field"
        list="builder-fields"
        placeholder="any field"
        value={field}
        onChange={(e) => setField(e.target.value)}
        aria-label="Field"
      />
      <datalist id="builder-fields">
        {fields.map((f) => (
          <option key={f.name} value={f.name}>
            {f.hint}
          </option>
        ))}
      </datalist>
      <select
        value={field ? op : 'contains'}
        disabled={!field}
        onChange={(e) => setOp(e.target.value as BuilderOp)}
        aria-label="Comparison"
      >
        {BUILDER_OPS.map(([v, label]) => (
          <option key={v} value={v}>
            {label}
          </option>
        ))}
      </select>
      <input
        className="builder-value"
        placeholder="value"
        value={operand}
        onChange={(e) => setOperand(e.target.value)}
        onKeyDown={(e) => e.key === 'Enter' && add()}
        aria-label="Value"
      />
      <button type="button" className="builder-add" disabled={!operand} onClick={add}>
        + Condition
      </button>

      <span className="builder-sep" aria-hidden="true" />

      <button
        type="button"
        className="builder-op"
        disabled={end !== 'term'}
        onClick={() => push(addOperator(value, 'AND'))}
      >
        AND
      </button>
      <button
        type="button"
        className="builder-op"
        disabled={end !== 'term'}
        onClick={() => push(addOperator(value, 'OR'))}
      >
        OR
      </button>
      <button type="button" className="builder-op" onClick={() => push(addNot(value))}>
        NOT
      </button>
      <button
        type="button"
        className="builder-op"
        title="Start a group"
        onClick={() => push(openBracket(value))}
      >
        (
      </button>
      <button
        type="button"
        className="builder-op"
        title="Close the group"
        disabled={open === 0 || end !== 'term'}
        onClick={() => push(closeBracket(value))}
      >
        )
      </button>
      {open > 0 && (
        <span className="builder-open">
          {open} open bracket{open > 1 ? 's' : ''}
        </span>
      )}

      <span className="spacer" />
      <button
        type="button"
        disabled={!canUndo}
        onClick={() => {
          setHistory((h) => h.slice(0, -1));
          onChange(last.before);
        }}
      >
        Undo
      </button>
      <button type="button" disabled={!value} onClick={() => push('')}>
        Clear
      </button>
    </div>
  );
}
