/** A parsed artifact record. Keys must match the parser's declared `columns`. */
export type Row = Record<string, unknown>;

/** Random-access byte source. Async so gigabyte files stream instead of loading whole. */
export interface Reader {
  readonly size: number;
  readonly name: string;
  /** Bytes at [offset, offset+length). Clamped at EOF — returns short, never throws. */
  bytes(offset: number, length: number): Promise<Uint8Array>;
}

export interface Warning {
  offset: number;
  message: string;
}

export interface Ctx {
  /**
   * Record a recoverable problem and keep going. Parsers must NOT throw on
   * malformed data: emit the rows they could recover and name what they could
   * not. A corrupt chunk loses that chunk, not the whole file.
   */
  warn(offset: number, message: string): void;
  signal?: AbortSignal;
}

export type ColType = 'str' | 'num' | 'date' | 'bool';

export interface Column {
  key: string;
  label: string;
  type?: ColType;
  /** Hidden from the default table view; still exported. */
  secondary?: boolean;
}

export interface Parser {
  /** Stable slug, used in URLs and exports. */
  id: string;
  /** Human name shown in the UI. */
  name: string;
  /** The Eric Zimmerman tool this replicates, for the mapping table. */
  ezTool: string;
  /** Lowercase, dot-prefixed. `[]` means match by magic bytes only. */
  extensions: string[];
  columns: Column[];
  /** Cheap check against the first 512 bytes + filename. No I/O. */
  sniff(head: Uint8Array, filename: string): boolean;
  parse(reader: Reader, ctx: Ctx): AsyncIterable<Row>;
}

export interface ParseOutcome {
  parserId: string;
  rows: Row[];
  warnings: Warning[];
}
