/**
 * Xpress Huffman (LZ77 + Huffman) decompression — [MS-XCA] section 2.2.
 *
 * Windows 10+ Prefetch files are stored compressed behind a `MAM\x04` header,
 * and nothing in the browser decompresses this: `DecompressionStream` covers
 * gzip and deflate only. So it is handwritten.
 *
 * Layout: the stream is a series of chunks, each decoding to exactly 65536
 * bytes except the last. Every chunk carries its own 256-byte table of 4-bit
 * code lengths for 512 symbols (low nibble first), followed by a bitstream read
 * as 16-bit little-endian words, most-significant bit first.
 *
 * Symbols 0-255 are literals. 256-511 encode a match: the low 4 bits are the
 * length nibble and the high 5 bits are the distance's bit width.
 */

const CHUNK = 65536;
const MAX_BITS = 15;

/** Thrown only for a stream that cannot be decoded at all; callers warn and continue. */
export class XpressError extends Error {}

/**
 * Builds a flat prefix-code lookup: index by the next 15 bits, get the symbol.
 * The table is 32768 entries, which is exactly the weight of a complete code,
 * so this costs one allocation per chunk and makes decoding a single index.
 */
function buildTable(lengths: Uint8Array): { sym: Uint16Array; len: Uint8Array } {
  const sym = new Uint16Array(1 << MAX_BITS);
  const len = new Uint8Array(1 << MAX_BITS);
  let code = 0;
  for (let bits = 1; bits <= MAX_BITS; bits++) {
    for (let s = 0; s < lengths.length; s++) {
      if (lengths[s] !== bits) continue;
      // Every 15-bit value starting with this code maps to this symbol.
      const shift = MAX_BITS - bits;
      const start = code << shift;
      const end = start + (1 << shift);
      if (end > sym.length) throw new XpressError('over-subscribed Huffman code');
      sym.fill(s, start, end);
      len.fill(bits, start, end);
      code++;
    }
    code <<= 1;
  }
  return { sym, len };
}

export function xpressHuffmanDecompress(input: Uint8Array, outputSize: number): Uint8Array {
  const out = new Uint8Array(outputSize);
  let outPos = 0;
  let pos = 0;

  while (outPos < outputSize) {
    const chunkStart = outPos;
    if (pos + 256 > input.length) throw new XpressError('truncated Huffman table');

    // 512 symbols packed two-per-byte, low nibble first.
    const lengths = new Uint8Array(512);
    for (let i = 0; i < 256; i++) {
      lengths[i * 2] = input[pos + i] & 0x0f;
      lengths[i * 2 + 1] = input[pos + i] >> 4;
    }
    const { sym, len } = buildTable(lengths);
    pos += 256;

    // 32-bit window over the 16-bit-word bitstream, MSB first. It is primed
    // with exactly two words and refilled one word at a time, only once fewer
    // than 16 bits remain. That timing is not cosmetic: extended match lengths
    // are read as raw bytes from this same `pos`, so refilling any more eagerly
    // reads those bytes from the wrong offset and desynchronises the stream.
    const nextWord = () => {
      const w = pos + 1 < input.length ? input[pos] | (input[pos + 1] << 8) : 0;
      pos += 2;
      return w;
    };
    const high = nextWord();
    const low = nextWord();
    let bitbuf = ((high << 16) | low) >>> 0;
    let bitcnt = 32;
    const fill = () => {
      if (bitcnt < 16) {
        bitbuf = (bitbuf | (nextWord() << (16 - bitcnt))) >>> 0;
        bitcnt += 16;
      }
    };

    // Output chunks are fixed 64 KiB slices, so a match never crosses one.
    const chunkEnd = Math.min(chunkStart + CHUNK, outputSize);
    while (outPos < chunkEnd) {
      fill();
      const idx = (bitbuf >>> (32 - MAX_BITS)) & 0x7fff;
      const s = sym[idx];
      const nbits = len[idx];
      if (nbits === 0) throw new XpressError(`invalid prefix code at output ${outPos}`);
      bitbuf = (bitbuf << nbits) >>> 0;
      bitcnt -= nbits;

      if (s < 256) {
        out[outPos++] = s;
        continue;
      }

      const matchSym = s - 256;
      let length = matchSym & 0x0f;
      const distBits = matchSym >> 4;

      fill();
      let distance = 1 << distBits;
      if (distBits > 0) {
        distance += (bitbuf >>> (32 - distBits)) & ((1 << distBits) - 1);
        bitbuf = (bitbuf << distBits) >>> 0;
        bitcnt -= distBits;
      }

      // A full length nibble means the real length follows in the byte stream,
      // which is interleaved after the 16-bit words the bit reader has consumed.
      if (length === 15) {
        if (pos >= input.length) throw new XpressError('truncated extended length');
        length = input[pos++] + 15;
        if (length === 270) {
          if (pos + 1 >= input.length) throw new XpressError('truncated 16-bit length');
          length = input[pos] | (input[pos + 1] << 8);
          pos += 2;
        }
      }
      length += 3;

      if (distance > outPos) throw new XpressError(`match distance ${distance} before output start`);
      // Overlapping copies are legal and common — copy byte by byte, stopping
      // at the chunk boundary rather than spilling into the next chunk.
      for (let i = 0; i < length && outPos < chunkEnd; i++) {
        out[outPos] = out[outPos - distance];
        outPos++;
      }
    }

    // The encoder pads each chunk's bitstream to a whole 16-bit word. If 16 or
    // more bits are still buffered that padding word has already been read; if
    // fewer remain it has not, so step over it before the next chunk's table.
    if (bitcnt < 16) pos += 2;
  }

  return out;
}

/**
 * Unwraps a `MAM\x04` container: 4-byte signature, then the uncompressed size,
 * then the Xpress Huffman stream. Returns the input unchanged when there is no
 * MAM header, so callers can hand any Prefetch file straight through.
 */
export function unwrapMam(buf: Uint8Array): Uint8Array {
  if (buf.length < 8 || buf[0] !== 0x4d || buf[1] !== 0x41 || buf[2] !== 0x4d) return buf;
  const size = (buf[4] | (buf[5] << 8) | (buf[6] << 16) | (buf[7] << 24)) >>> 0;
  return xpressHuffmanDecompress(buf.subarray(8), size);
}
