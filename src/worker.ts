/// <reference lib="webworker" />
import { blobReader } from './core/reader';
import { byId, detect, parsers, run } from './core/registry';
import type { Column } from './core/types';
import './parsers';

export interface WorkRequest {
  id: number;
  file: File;
  /** Force a parser instead of sniffing. */
  parserId?: string;
}

/** What the worker can read, announced once so the UI never lists a stale set. */
export interface ParserInfo {
  id: string;
  name: string;
  ezTool: string;
  extensions: string[];
}

export interface WorkerReady {
  ready: true;
  parsers: ParserInfo[];
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

// Announced on startup rather than hard-coded in the UI: a parser added here
// should show up in the interface without anyone remembering to update it.
self.postMessage({
  ready: true,
  parsers: parsers.map((p) => ({
    id: p.id,
    name: p.name,
    ezTool: p.ezTool,
    extensions: p.extensions,
  })),
} satisfies WorkerReady);

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
