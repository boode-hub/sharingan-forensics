import { describe, expect, it } from 'vitest';
import { isColour, isPosition, isSavedList, upsert, type SavedFilter } from './storage';

const f = (name: string, parserId = 'evtx', search = ''): SavedFilter => ({
  name,
  parserId,
  search,
  columns: {},
  sigma: null,
});

describe('saved filters', () => {
  it('replaces a filter saved again under the same name', () => {
    const list = upsert([f('logons', 'evtx', '4624')], f('logons', 'evtx', '4624 OR 4625'));
    expect(list).toHaveLength(1);
    expect(list[0].search).toBe('4624 OR 4625');
  });

  it('keeps same-named filters for different kinds of artifact apart', () => {
    expect(upsert([f('mine', 'evtx')], f('mine', 'registry'))).toHaveLength(2);
  });

  it('keeps the list in name order', () => {
    expect(upsert([f('b'), f('c')], f('a')).map((x) => x.name)).toEqual(['a', 'b', 'c']);
  });

  it('rejects stored data that is not a list of filters', () => {
    // Storage is outside the program's control; a corrupt or hand-edited
    // entry must fall back to nothing rather than crash the page.
    expect(isSavedList([f('ok')])).toBe(true);
    expect(isSavedList([{ name: 'x' }])).toBe(false);
    expect(isSavedList({})).toBe(false);
    expect(isSavedList([{ ...f('x'), columns: { a: 1 } }])).toBe(false);
  });
});

describe('preferences', () => {
  it('accepts only the three detail positions', () => {
    expect(isPosition('left')).toBe(true);
    expect(isPosition('top')).toBe(false);
  });

  it('accepts only a hex colour', () => {
    expect(isColour('#9fef00')).toBe(true);
    expect(isColour('red')).toBe(false);
    expect(isColour('#9fef0')).toBe(false);
  });
});
