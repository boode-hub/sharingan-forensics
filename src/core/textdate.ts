/**
 * Dates Windows stores as text, read the way Eric Zimmerman's tools read them
 * with .NET's DateTime.Parse: Amcache's "07/13/2009 23:32:37", a zip folder
 * shell item's access time.
 */
/**
 * DateTime.Parse with the invariant culture, which is how he reads the dates
 * Windows stores as text ("07/13/2009 23:32:37", month first). He then takes
 * the result as UTC without converting it.
 */
export function invariantDate(s: string): Date | null {
  let m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d{1,7}))?)?\s*(AM|PM)?)?$/i.exec(
    s.trim(),
  );
  let y: number, mo: number, d: number, h: number, mi: number, sec: number, frac: string;
  if (m) {
    [mo, d, y, h, mi, sec] = [m[1], m[2], m[3], m[4] ?? '0', m[5] ?? '0', m[6] ?? '0'].map(Number);
    frac = m[7] ?? '';
    const ampm = m[8]?.toUpperCase();
    if (ampm && (h < 1 || h > 12)) return null;
    if (ampm === 'PM' && h < 12) h += 12;
    if (ampm === 'AM' && h === 12) h = 0;
  } else {
    m = /^(\d{4})-(\d{1,2})-(\d{1,2})(?:[T ](\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d{1,7}))?)?)?(Z|[+-]\d{2}:?\d{2})?$/.exec(
      s.trim(),
    );
    if (!m) return null;
    [y, mo, d, h, mi, sec] = [m[1], m[2], m[3], m[4] ?? '0', m[5] ?? '0', m[6] ?? '0'].map(Number);
    frac = m[7] ?? '';
  }
  const ms = Number(frac.padEnd(3, '0').slice(0, 3));
  const t = Date.UTC(y, mo - 1, d, h, mi, sec, ms);
  const date = new Date(t);
  // Date.UTC rolls 02/30 into March; DateTime.Parse rejects it.
  if (date.getUTCMonth() !== mo - 1 || date.getUTCDate() !== d || h > 23 || mi > 59 || sec > 59) return null;
  if (y < 1) return null;
  return date;
}

