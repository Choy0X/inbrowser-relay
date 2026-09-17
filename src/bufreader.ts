/**
 * A small buffered reader over a ReadableStream of bytes.
 *
 * Pure: it takes a reader, never a socket, which is what lets the handshake
 * modules that use it run unmodified under Node in `npm run verify:relay`.
 *
 * The one method that matters more than it looks is `takeLeftover()`. A proxy is
 * entitled to coalesce its handshake reply and the first bytes of the tunnel
 * into a single TCP segment, so by the time the handshake has parsed its reply
 * this buffer may already hold the first bytes of the TLS ServerHello. Dropping
 * them corrupts the TLS session in a way that surfaces much later as a generic
 * handshake failure, with nothing pointing back here. Every handshake returns
 * its leftover and the pipe writes it out before anything else.
 */

export class BufferedReader {
  private chunks: Uint8Array[] = [];
  private size = 0;
  private done = false;

  constructor(private readonly reader: ReadableStreamDefaultReader<Uint8Array>) {}

  private take(n: number): Uint8Array {
    const out = new Uint8Array(n);
    let offset = 0;
    while (offset < n) {
      const head = this.chunks[0];
      const need = n - offset;
      if (head.length <= need) {
        out.set(head, offset);
        offset += head.length;
        this.chunks.shift();
      } else {
        out.set(head.subarray(0, need), offset);
        this.chunks[0] = head.subarray(need);
        offset += need;
      }
    }
    this.size -= n;
    return out;
  }

  private async pull(): Promise<boolean> {
    if (this.done) return false;
    const { value, done } = await this.reader.read();
    if (done) {
      this.done = true;
      return false;
    }
    if (value && value.length > 0) {
      this.chunks.push(value);
      this.size += value.length;
    }
    return true;
  }

  /** Reads exactly n bytes, or throws if the stream ends first. */
  async readExact(n: number): Promise<Uint8Array> {
    while (this.size < n) {
      if (!(await this.pull())) {
        throw new Error("The connection closed before the proxy finished replying.");
      }
    }
    return this.take(n);
  }

  /**
   * Reads up to and including `delim`. `cap` bounds how much will be buffered
   * before giving up, so a proxy that answers CONNECT with an endless header
   * block cannot exhaust memory.
   */
  async readUntil(delim: Uint8Array, cap: number): Promise<Uint8Array> {
    let searched = 0;
    for (;;) {
      const flat = this.peek();
      const at = indexOfSub(flat, delim, Math.max(0, searched - delim.length + 1));
      if (at !== -1) return this.take(at + delim.length);
      searched = flat.length;
      if (this.size > cap) throw new Error("The proxy sent an oversized reply.");
      if (!(await this.pull())) {
        throw new Error("The connection closed before the proxy finished replying.");
      }
    }
  }

  /** Flattens the buffer without consuming it. Only used for delimiter scans. */
  private peek(): Uint8Array {
    if (this.chunks.length === 1) return this.chunks[0];
    if (this.chunks.length === 0) return new Uint8Array(0);
    const flat = new Uint8Array(this.size);
    let offset = 0;
    for (const chunk of this.chunks) {
      flat.set(chunk, offset);
      offset += chunk.length;
    }
    this.chunks = [flat];
    return flat;
  }

  /**
   * Everything buffered past the handshake. See the note at the top of this
   * file - these bytes are the start of the tunnel and must not be dropped.
   */
  takeLeftover(): Uint8Array {
    if (this.size === 0) return new Uint8Array(0);
    return this.take(this.size);
  }
}

function indexOfSub(haystack: Uint8Array, needle: Uint8Array, from: number): number {
  if (needle.length === 0) return 0;
  const limit = haystack.length - needle.length;
  outer: for (let i = Math.max(0, from); i <= limit; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}
