// The part of sql.js (SQLite compiled to WebAssembly) this app uses.
declare module 'sql.js' {
  export type SqlValue = number | bigint | string | Uint8Array | null;
  export interface Statement {
    step(): boolean;
    getColumnNames(): string[];
    get(params?: null, config?: { useBigInt?: boolean }): SqlValue[];
    free(): boolean;
  }
  export interface Database {
    prepare(sql: string): Statement;
    close(): void;
  }
  export interface SqlJsStatic {
    Database: new (data?: Uint8Array) => Database;
  }
  export default function initSqlJs(config?: {
    instantiateWasm?: (
      imports: WebAssembly.Imports,
      done: (instance: WebAssembly.Instance) => void,
    ) => Record<string, never>;
  }): Promise<SqlJsStatic>;
}
