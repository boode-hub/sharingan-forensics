/**
 * Building a filter a condition at a time, with buttons for AND, OR, NOT and
 * brackets. Everything it builds is ordinary filter-language text (see
 * query.ts), so what the buttons produce is visible in the search box and can
 * be edited there by hand.
 */

export type BuilderOp = 'contains' | '=' | '!=' | 'startswith' | 'endswith' | '>' | '>=' | '<' | '<=';

export const BUILDER_OPS: Array<[BuilderOp, string]> = [
  ['contains', 'contains'],
  ['=', 'equals'],
  ['!=', 'does not equal'],
  ['startswith', 'starts with'],
  ['endswith', 'ends with'],
  ['>', '>'],
  ['>=', '≥'],
  ['<', '<'],
  ['<=', '≤'],
];

/** Quotes a value the filter language would otherwise read as syntax. */
export function quote(value: string): string {
  const needs =
    value === '' ||
    /[\s()"]/.test(value) ||
    /^[-!]/.test(value) ||
    /^(and|or|not)$/i.test(value) ||
    /^(&&|\|\|)$/.test(value);
  return needs ? `"${value.replace(/"/g, '')}"` : value;
}

/** One condition as filter text. No field means the value anywhere in the row. */
export function condition(field: string, op: BuilderOp, value: string): string {
  const f = field.trim();
  if (!f) return quote(value);
  if (op === 'contains' || op === 'startswith' || op === 'endswith') return `${f} ${op} ${quote(value)}`;
  return `${f}${op}${quote(value)}`;
}

/** What the text ends with, which decides what may come next. */
export function ending(text: string): 'start' | 'open' | 'operator' | 'term' {
  const t = text.trimEnd();
  if (t === '') return 'start';
  if (t.endsWith('(')) return 'open';
  if (/(^|[\s(])(and|or|not|&&|\|\|)$/i.test(t)) return 'operator';
  return 'term';
}

/** Brackets opened and not yet closed, ignoring any inside quotes. */
export function openBrackets(text: string): number {
  let open = 0;
  let quoted = false;
  for (const c of text) {
    if (c === '"') quoted = !quoted;
    else if (!quoted && c === '(') open++;
    else if (!quoted && c === ')' && open > 0) open--;
  }
  return open;
}

function join(text: string, piece: string): string {
  const t = text.trimEnd();
  if (t === '' || t.endsWith('(')) return t + piece;
  return `${t} ${piece}`;
}

/** Adds a condition; two conditions in a row are joined with AND. */
export function addCondition(text: string, cond: string): string {
  return join(ending(text) === 'term' ? join(text, 'AND') : text, cond);
}

export function addOperator(text: string, op: 'AND' | 'OR'): string {
  return ending(text) === 'term' ? join(text, op) : text;
}

export function addNot(text: string): string {
  return join(ending(text) === 'term' ? join(text, 'AND') : text, 'NOT');
}

export function openBracket(text: string): string {
  return join(ending(text) === 'term' ? join(text, 'AND') : text, '(');
}

export function closeBracket(text: string): string {
  return openBrackets(text) > 0 && ending(text) === 'term' ? `${text.trimEnd()})` : text;
}
