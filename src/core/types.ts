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
   * Other files opened alongside this one, when the artifact is only half the
   * story on its own. A registry hive needs its transaction logs to be read as
   * the machine would have read it; without them the answer is whatever was
   * true when the hive was last flushed.
   */
  siblings?: Reader[];
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

/**
 * One of several kinds of record an artifact holds, as his tools write one CSV
 * per kind (AmcacheParser's ProgramEntries, ShortCuts, DriverBinaries...).
 */
export interface Table {
  id: string;
  label: string;
  columns: Column[];
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
  /**
   * For an artifact with several kinds of record, one table per kind. Each row
   * then carries `table`, the id of the table it belongs to, and has that
   * table's columns; `columns` is the first table's.
   */
  tables?: Table[];
  /**
   * Never chosen automatically, only when an analyst asks for it.
   *
   * Some artifacts live inside another one: shell bags are a structure within
   * a registry hive, not a file. Dropping a UsrClass.dat should give the hive,
   * because that is what the file is; reading it as shell bags is a second
   * question about the same bytes, and the analyst is the one who asks it.
   */
  manual?: boolean;
  /** Cheap check against the first 512 bytes + filename. No I/O. */
  sniff(head: Uint8Array, filename: string): boolean;
  parse(reader: Reader, ctx: Ctx): AsyncIterable<Row>;
}

export interface ParseOutcome {
  parserId: string;
  rows: Row[];
  warnings: Warning[];
}
