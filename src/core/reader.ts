import type { Reader } from './types';

/** Streams from a File/Blob — never loads the whole thing. Use for user uploads. */
export function blobReader(blob: Blob, name = (blob as File).name ?? 'blob'): Reader {
  return {
    size: blob.size,
    name,
    async bytes(offset, length) {
      const start = Math.max(0, Math.min(offset, blob.size));
      const end = Math.max(start, Math.min(offset + length, blob.size));
      return new Uint8Array(await blob.slice(start, end).arrayBuffer());
    },
  };
}

/** In-memory source. Use for tests and for embedded streams inside a container. */
export function bufReader(buf: Uint8Array, name = 'buffer'): Reader {
  return {
    size: buf.length,
    name,
    async bytes(offset, length) {
      const start = Math.max(0, Math.min(offset, buf.length));
      const end = Math.max(start, Math.min(offset + length, buf.length));
      return buf.subarray(start, end);
    },
  };
}
