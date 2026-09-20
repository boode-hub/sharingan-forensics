import type { Ctx, ParseOutcome, Parser, Reader, Row, Warning } from './types';

/**
 * Every implemented parser. Append here when adding one — deliberately a plain
 * array, not a plugin system. Order matters only as a tiebreak in `detect`.
 */
export const parsers: Parser[] = [];

export function register(...p: Parser[]): void {
  for (const x of p) {
    if (parsers.some((e) => e.id === x.id)) throw new Error(`duplicate parser id: ${x.id}`);
    parsers.push(x);
  }
}

export function byId(id: string): Parser | undefined {
  return parsers.find((p) => p.id === id);
}

/**
 * Picks a parser by magic bytes first, extension second. Returns null when
 * nothing claims the file — the caller shows "unrecognised", never guesses.
 */
export async function detect(reader: Reader): Promise<Parser | null> {
  const head = await reader.bytes(0, 512);
  const name = reader.name.toLowerCase();
  const ext = name.slice(name.lastIndexOf('.'));
  const hits = parsers.filter((p) => p.sniff(head, name));
  if (hits.length) return hits[0];
  return parsers.find((p) => p.extensions.includes(ext)) ?? null;
}

const MAX_ROWS = 2_000_000;

/**
 * Runs a parser to completion, collecting rows and warnings.
 *
 * A parser that throws anyway still returns the rows it produced before the
 * throw, with the failure recorded as a warning. Losing the tail of a corrupt
 * artifact must never cost the analyst the records that parsed cleanly.
 */
export async function run(
  parser: Parser,
  reader: Reader,
  signal?: AbortSignal,
): Promise<ParseOutcome> {
  const rows: Row[] = [];
  const warnings: Warning[] = [];
  const ctx: Ctx = {
    warn: (offset, message) => {
      // Cap the channel so a pathological loop can't exhaust memory with warnings.
      if (warnings.length < 1000) warnings.push({ offset, message });
      else if (warnings.length === 1000)
        warnings.push({ offset, message: 'further warnings suppressed' });
    },
    signal,
  };

  try {
    for await (const row of parser.parse(reader, ctx)) {
      if (signal?.aborted) {
        ctx.warn(0, 'parsing cancelled — results are partial');
        break;
      }
      rows.push(row);
      if (rows.length >= MAX_ROWS) {
        ctx.warn(0, `row cap of ${MAX_ROWS.toLocaleString()} reached — results are partial`);
        break;
      }
    }
  } catch (e) {
    ctx.warn(0, `parser failed after ${rows.length} rows: ${(e as Error).message}`);
  }

  return { parserId: parser.id, rows, warnings };
}
