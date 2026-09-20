/// <reference lib="webworker" />
import { blobReader } from './core/reader';
import { byId, detect, run } from './core/registry';
import type { Column } from './core/types';
import './parsers';

export interface WorkRequest {
  id: number;
  file: File;
  /** Force a parser instead of sniffing. */
  parserId?: string;
}

export interface WorkResult {
  id: number;
  fileName: string;
  fileSize: number;
  parser?: { id: string; name: string; ezTool: string; columns: Column[] };
  rows?: Record<string, unknown>[];
  warnings?: { offset: number; message: string }[];
  ms?: number;
  error?: string;
}

self.onmessage = async (e: MessageEvent<WorkRequest>) => {
  const { id, file, parserId } = e.data;
  const started = performance.now();
  const reader = blobReader(file, file.name);
  const base = { id, fileName: file.name, fileSize: file.size };

  const parser = parserId ? byId(parserId) : await detect(reader);
  if (!parser) {
    self.postMessage({
      ...base,
      error: 'No parser recognised this file. Pick one manually if you know the format.',
    } satisfies WorkResult);
    return;
  }

  const outcome = await run(parser, reader);
  self.postMessage({
    ...base,
    parser: {
      id: parser.id,
      name: parser.name,
      ezTool: parser.ezTool,
      columns: parser.columns,
    },
    rows: outcome.rows,
    warnings: outcome.warnings,
    ms: Math.round(performance.now() - started),
  } satisfies WorkResult);
};
