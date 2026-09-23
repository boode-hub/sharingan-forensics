import { describe, expect, it } from 'vitest';
import type { Column, Row } from '../core/types';
import {
  addCondition,
  addNot,
  addOperator,
  closeBracket,
  condition,
  ending,
  openBracket,
  openBrackets,
} from './builder';
import { compileQuery } from './query';

const columns: Column[] = [
  { key: 'eventId', label: 'Event Id', type: 'num' },
  { key: 'user', label: 'User', type: 'str' },
];

describe('building a filter with buttons', () => {
  it('writes AND, then a bracketed OR, as the analyst pressed them', () => {
    let q = '';
    q = addCondition(q, condition('eventId', '=', '4624'));
    q = addOperator(q, 'AND');
    q = openBracket(q);
    q = addCondition(q, condition('user', 'contains', 'admin'));
    q = addOperator(q, 'OR');
    q = addCondition(q, condition('user', '=', 'bob smith'));
    q = closeBracket(q);
    expect(q).toBe('eventId=4624 AND (user contains admin OR user="bob smith")');

    // And the text means what the buttons said.
    const test = compileQuery(q, columns);
    const rows: Row[] = [
      { eventId: 4624, user: 'administrator' },
      { eventId: 4624, user: 'bob smith' },
      { eventId: 4624, user: 'carol' },
      { eventId: 4625, user: 'admin' },
    ];
    expect(rows.filter(test).map((r) => r.user)).toEqual(['administrator', 'bob smith']);
  });

  it('joins two conditions with AND when no operator was pressed', () => {
    expect(addCondition('eventId=4624', 'svchost')).toBe('eventId=4624 AND svchost');
  });

  it('ignores an operator with nothing before it to join', () => {
    expect(addOperator('', 'OR')).toBe('');
    expect(addOperator('a AND', 'OR')).toBe('a AND');
    expect(addOperator('(', 'AND')).toBe('(');
  });

  it('closes a bracket only after a condition, and only one that is open', () => {
    expect(closeBracket('a')).toBe('a');
    expect(closeBracket('(a OR')).toBe('(a OR');
    expect(closeBracket('(a OR b')).toBe('(a OR b)');
    expect(openBrackets('(a OR "b (c")')).toBe(0);
  });

  it('quotes values the language would read as syntax', () => {
    expect(condition('', 'contains', '-enc')).toBe('"-enc"');
    expect(condition('cmd', 'contains', 'a b')).toBe('cmd contains "a b"');
    expect(condition('', 'contains', 'OR')).toBe('"OR"');
    expect(addNot('')).toBe('NOT');
    expect(ending('a NOT')).toBe('operator');
  });
});
