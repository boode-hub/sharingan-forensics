/**
 * The filter language, used by the search box and by every column filter.
 *
 *   powershell                     any column contains "powershell"
 *   "C:\Program Files"             a phrase, spaces and all
 *   4624 OR 4625                   either
 *   admin AND -svchost             both conditions; "-" excludes (also NOT, !)
 *   (4624 OR 4625) NOT system      grouping
 *   EventId:4624                   that field contains 4624
 *   EventId=4624                   that field is exactly 4624
 *   CommandLine contains -enc      also startswith, endswith
 *   TimeCreated>=2024-01-01        dates compare as time, numbers as numbers
 *   Image:*\powershell.exe         * and ? are wildcards
 *
 * Terms next to each other are ANDed. AND, OR and NOT may be written in either
 * case, or as &&, || and a leading - or !. A field is a column, by key or by
 * label, or a field inside an event's payload such as TargetUserName; words
 * that are not a known field are searched for as text, so C:\Windows is a path
 * and not a field called C.
 *
 * A value that begins with "-" has to be quoted to be searched for rather than
 * excluded: "-enc", not -enc. That matters for command lines.
 */
import type { Column, Row } from '../core/types';
import { columnIndex, fieldValues, norm } from './fields';
import { fmt } from './format';

/**
 * Matches one value against a comparison the way a column filter always has.
 *
 * Plain text is a case-insensitive substring match. The operators exist
 * because substring alone cannot ask the two questions forensics asks of a
 * large table: "only this window of time" and "only these ids".
 *
 *   4624          contains "4624"
 *   !svchost      does NOT contain "svchost"
 *   >=2019-02-13  on or after that instant — dates compare as time, not text
 *   <100          numerically less than 100
 *   =4624         exactly equal, so 4624 does not also match 14624
 */
export function matches(value: unknown, expr: string): boolean {
  const e = expr.trim();
  if (!e) return true;
  if (e.startsWith('!')) return !matches(value, e.slice(1));

  const op = /^(>=|<=|>|<|=)(.*)$/.exec(e);
  if (!op) return fmt(value).toLowerCase().includes(e.toLowerCase());

  const [, operator, raw] = op;
  const operand = raw.trim();
  if (!operand) return true;

  // Compare as time when the cell is a date and as number when both sides are
  // numeric; fall back to text so the operators still behave sensibly on
  // strings rather than silently matching nothing.
  let a: number | string;
  let b: number | string;
  if (value instanceof Date) {
    // Cells are displayed as ISO UTC, so a bare "2019-02-13T15:00" must mean
    // 15:00 UTC too. JavaScript would otherwise read a date-time with no zone
    // as LOCAL time, so the same text would select a different set of events
    // depending on the analyst's machine — unacceptable in forensic output.
    const hasZone = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(operand);
    const t = Date.parse(hasZone || !operand.includes('T') ? operand : `${operand}Z`);
    if (Number.isNaN(t)) return false;
    a = value.getTime();
    b = t;
  } else if (
    (typeof value === 'number' || (typeof value === 'string' && /^-?\d+(\.\d+)?$/.test(value))) &&
    !Number.isNaN(Number(operand))
  ) {
    // Fields read out of an event payload are text even when they hold a
    // number, so "LogonType>2" has to compare 10 as ten, not as "1".
    a = Number(value);
    b = Number(operand);
  } else {
    a = fmt(value).toLowerCase();
    b = operand.toLowerCase();
  }

  if (operator === '=') return a === b;
  if (operator === '>') return a > b;
  if (operator === '<') return a < b;
  if (operator === '>=') return a >= b;
  return a <= b;
}

type Op = 'has' | '=' | '!=' | '>' | '>=' | '<' | '<=' | 'contains' | 'startswith' | 'endswith';

type Node =
  | { kind: 'and' | 'or'; items: Node[] }
  | { kind: 'not'; item: Node }
  | {
      kind: 'leaf';
      field: string | null;
      op: Op;
      value: string;
      /** The term as typed, searched for as text when the field is not there. */
      raw: string;
    };

type Token =
  | { t: '(' | ')' | 'and' | 'or' | 'not' }
  | { t: 'word'; text: string; quoted: boolean };

const WORD_OPS = new Set(['contains', 'startswith', 'endswith']);

function tokenize(input: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  while (i < input.length) {
    const ch = input[i];
    if (/\s/.test(ch)) {
      i++;
      continue;
    }
    if (ch === '(' || ch === ')') {
      out.push({ t: ch });
      i++;
      continue;
    }
    if (input.startsWith('&&', i)) {
      out.push({ t: 'and' });
      i += 2;
      continue;
    }
    if (input.startsWith('||', i)) {
      out.push({ t: 'or' });
      i += 2;
      continue;
    }
    // A leading - or ! negates what follows, but only at the start of a term:
    // the dashes inside 2019-02-13 are part of the date.
    if ((ch === '-' || ch === '!') && i + 1 < input.length && !/[\s=)]/.test(input[i + 1])) {
      out.push({ t: 'not' });
      i++;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let text = '';
      while (j < input.length && input[j] !== '"') {
        if (input[j] === '\\' && input[j + 1] === '"') {
          text += '"';
          j += 2;
          continue;
        }
        text += input[j++];
      }
      out.push({ t: 'word', text, quoted: true });
      i = j + 1;
      continue;
    }
    let j = i;
    while (j < input.length && !/[\s()]/.test(input[j])) {
      // A quote straight after an operator belongs to this term: Name:"a b".
      if (input[j] === '"' && j > i && /[:=<>]$/.test(input.slice(i, j))) {
        let k = j + 1;
        while (k < input.length && input[k] !== '"') k++;
        j = k + 1;
        break;
      }
      j++;
    }
    const text = input.slice(i, j);
    const lower = text.toLowerCase();
    if (lower === 'and') out.push({ t: 'and' });
    else if (lower === 'or') out.push({ t: 'or' });
    else if (lower === 'not') out.push({ t: 'not' });
    else out.push({ t: 'word', text, quoted: false });
    i = j;
  }
  return out;
}

export class QueryError extends Error {}

/**
 * Splits "Field>=value" into its parts, but only when the part before the
 * operator is a field this table knows. Otherwise the whole word is a value:
 * "C:\Windows" is a path, not the field C.
 */
function splitTerm(text: string, isField: (name: string) => boolean): Node {
  const m = /^([^:=<>!]+?)(!=|>=|<=|=|>|<|:)(.*)$/s.exec(text);
  if (m && isField(m[1])) {
    const op: Op = m[2] === ':' ? 'has' : (m[2] as Op);
    return { kind: 'leaf', field: m[1], op, value: unquote(m[3]), raw: text };
  }
  // A bare comparison such as ">=2019-02-13" applies to the column it is typed in.
  const bare = /^(!=|>=|<=|=|>|<)(.+)$/s.exec(text);
  if (bare) {
    return { kind: 'leaf', field: null, op: bare[1] as Op, value: unquote(bare[2]), raw: text };
  }
  return { kind: 'leaf', field: null, op: 'has', value: text, raw: text };
}

function unquote(s: string): string {
  return s.length >= 2 && s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1) : s;
}

function parse(tokens: Token[], isField: (name: string) => boolean): Node {
  let pos = 0;
  const peek = () => tokens[pos];

  const orExpr = (): Node => {
    const items = [andExpr()];
    while (peek()?.t === 'or') {
      pos++;
      items.push(andExpr());
    }
    return items.length === 1 ? items[0] : { kind: 'or', items };
  };

  const andExpr = (): Node => {
    const items = [notExpr()];
    for (;;) {
      const t = peek();
      if (!t || t.t === ')' || t.t === 'or') break;
      if (t.t === 'and') pos++;
      items.push(notExpr());
    }
    return items.length === 1 ? items[0] : { kind: 'and', items };
  };

  const notExpr = (): Node => {
    if (peek()?.t === 'not') {
      pos++;
      return { kind: 'not', item: notExpr() };
    }
    return primary();
  };

  const primary = (): Node => {
    const t = tokens[pos++];
    if (!t) throw new QueryError('the filter ends where a term was expected');
    if (t.t === '(') {
      const inner = orExpr();
      if (tokens[pos++]?.t !== ')') throw new QueryError('a "(" is never closed');
      return inner;
    }
    if (t.t !== 'word') throw new QueryError(`"${t.t.toUpperCase()}" is missing something to apply to`);
    if (t.quoted) return { kind: 'leaf', field: null, op: 'has', value: t.text, raw: t.text };

    // "Field contains value", as three words.
    const next = tokens[pos];
    if (
      next?.t === 'word' &&
      !next.quoted &&
      WORD_OPS.has(next.text.toLowerCase()) &&
      isField(t.text)
    ) {
      const value = tokens[pos + 1];
      if (!value || value.t !== 'word') {
        throw new QueryError(`"${next.text}" needs a value after it`);
      }
      pos += 2;
      return {
        kind: 'leaf',
        field: t.text,
        op: next.text.toLowerCase() as Op,
        value: value.text,
        raw: `${t.text} ${next.text} ${value.text}`,
      };
    }
    // "Field:" followed by a quoted value, as two tokens.
    if (/[:=<>]$/.test(t.text) && next?.t === 'word' && next.quoted) {
      pos++;
      return splitTerm(`${t.text}"${next.text}"`, isField);
    }
    return splitTerm(t.text, isField);
  };

  const tree = orExpr();
  if (pos < tokens.length) {
    const t = tokens[pos];
    throw new QueryError(t.t === ')' ? 'a ")" has no "(" to close' : 'the filter could not be read');
  }
  return tree;
}

/** Wildcard pattern to a regular expression: * is any run, ? any one character. */
function glob(pattern: string): RegExp {
  const src = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${src}$`, 'is');
}

function leafTest(value: unknown, op: Op, operand: string): boolean {
  switch (op) {
    case 'has': {
      if (/[*?]/.test(operand)) return glob(operand).test(fmt(value));
      return fmt(value).toLowerCase().includes(operand.toLowerCase());
    }
    case 'contains':
      return fmt(value).toLowerCase().includes(operand.toLowerCase());
    case 'startswith':
      return fmt(value).toLowerCase().startsWith(operand.toLowerCase());
    case 'endswith':
      return fmt(value).toLowerCase().endsWith(operand.toLowerCase());
    case '=':
      return /[*?]/.test(operand) ? glob(operand).test(fmt(value)) : matches(value, `=${operand}`);
    case '!=':
      return !leafTest(value, '=', operand);
    default:
      return matches(value, `${op}${operand}`);
  }
}

export type Predicate = (row: Row) => boolean;

/**
 * Compiles a filter into a test over rows.
 *
 * `defaultField` is the column a column filter was typed into: there, a bare
 * term means that column. In the search box it is absent, and a bare term
 * means any column.
 */
export function compileQuery(text: string, columns: Column[], defaultField?: string): Predicate {
  const trimmed = text.trim();
  if (!trimmed) return () => true;

  const index = columnIndex(columns);
  // A name is a field if it is a column or a plausible payload field name.
  // Payload fields cannot be listed in advance, so anything shaped like an
  // identifier is allowed, and text such as "C:\Windows" is not.
  const isField = (name: string) => index.has(norm(name)) || /^[A-Za-z_][\w.]*$/.test(name);

  const tree = parse(tokenize(trimmed), isField);
  const keys = columns.map((c) => c.key);

  const evaluate = (node: Node, row: Row): boolean => {
    switch (node.kind) {
      case 'and':
        return node.items.every((n) => evaluate(n, row));
      case 'or':
        return node.items.some((n) => evaluate(n, row));
      case 'not':
        return !evaluate(node.item, row);
      case 'leaf': {
        if (node.field === null) {
          // No field named: the column this filter belongs to, or else any
          // column at all.
          if (defaultField !== undefined) return leafTest(row[defaultField], node.op, node.value);
          return keys.some((k) => leafTest(row[k], node.op, node.value));
        }
        const values = fieldValues(row, node.field, index);
        if (values.length === 0 && !index.has(norm(node.field))) {
          // Not a column, and not a field this row has either, so it was never
          // a field: "http://host" is an address, not the field "http".
          const target = defaultField !== undefined ? [defaultField] : keys;
          return target.some((k) => leafTest(row[k], 'has', node.raw));
        }
        return values.some((v) => leafTest(v, node.op, node.value));
      }
    }
  };

  return (row: Row) => evaluate(tree, row);
}

/** Checks a filter without running it, for showing a mistake as it is typed. */
export function queryError(text: string, columns: Column[]): string | null {
  try {
    compileQuery(text, columns);
    return null;
  } catch (e) {
    return e instanceof QueryError ? e.message : String(e);
  }
}
