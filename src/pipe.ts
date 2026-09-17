/**
 * The post-handshake pump. Everything from here on is opaque: these bytes are
 * the VPS's TLS session with the provider, and the Worker has no key material
 * for it and never will.
 *
 * Two things here are less obvious than they look.
 *
 * 1. Writes toward the proxy are serialised through a single promise chain.
 *    `WritableStreamDefaultWriter.write()` must not be called again before the
 *    previous call settles; doing so from a WebSocket message listener, which
 *    fires whenever it likes, reorders chunks. A reordered TLS record stream
 *    fails as a decryption error at the far end, which points nowhere near
 *    here. The chain is the fix and it is not optional.
 *
 * 2. There is no usable backpressure signal on the server-side WebSocket in
 *    workerd, so a fast upstream can outrun a slow client. The byte and
 *    duration caps below are what bound that, rather than flow control.
 */
import { RelayClose } from "./protocol";

export interface PipeLimits {
  /** Total bytes in either direction before the connection is cut. */
  maxBytes: number;
  /** Wall-clock ceiling for one tunnel. */
  maxDurationMs: number;
  /** Silence in both directions before the connection is considered dead. */
  idleMs: number;
}

export const DEFAULT_LIMITS: PipeLimits = {
  maxBytes: 64 * 1024 * 1024,
  maxDurationMs: 10 * 60 * 1000,
  idleMs: 60 * 1000,
};

/**
 * Neither `cloudflare:sockets`' writable-stream `write()` nor a Worker's own
 * outgoing WebSocket `send()` has a documented per-call size ceiling, but a
 * single very large call to either is the one thing observed to fail
 * outright (the write rejects, or the message never arrives) rather than
 * simply queuing or backpressuring like a normal stream. An uploaded image's
 * bytes arrive here as far fewer, far larger WebSocket messages than a plain
 * text turn ever produces - segmenting anything over this size before handing
 * it to either primitive removes the failure mode entirely at the cost of a
 * few extra small writes, and is invisible to both ends: the proxy and the
 * VPS relay each just see the same bytes, in the same order, as more/smaller
 * pieces instead of one large one.
 */
const MAX_SOCKET_CHUNK_BYTES = 64 * 1024;

/** Yields `data` in `MAX_SOCKET_CHUNK_BYTES`-sized pieces, unchanged if already smaller. */
function* chunked(data: Uint8Array): Generator<Uint8Array> {
  if (data.length <= MAX_SOCKET_CHUNK_BYTES) {
    yield data;
    return;
  }
  for (let offset = 0; offset < data.length; offset += MAX_SOCKET_CHUNK_BYTES) {
    yield data.subarray(offset, offset + MAX_SOCKET_CHUNK_BYTES);
  }
}

interface Sock {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  close(): Promise<void> | void;
}

/** Resolves after both pumps and TCP cleanup settle, for the session's waitUntil. */
export function pipe(ws: WebSocket, socket: Sock, leftover: Uint8Array, limits: PipeLimits = DEFAULT_LIMITS): Promise<void> {
  const writer = socket.writable.getWriter();
  let bytes = 0;
  let closed = false;
  let writeChain: Promise<unknown> = Promise.resolve();
  let closing: Promise<void> = Promise.resolve();

  const shutdown = (code: number, reason = "") => {
    if (closed) return;
    closed = true;
    clearTimeout(durationTimer);
    clearTimeout(idleTimer);
    try {
      // A close reason is capped at 123 bytes by the protocol; the codes carry
      // the meaning and protocol.ts maps them back to text on the other side.
      ws.close(code, reason.slice(0, 120));
    } catch {
      /* already closing */
    }
    try {
      writer.releaseLock();
    } catch {
      /* mid-write */
    }
    try {
      // close() can reject after this synchronous try has returned, especially
      // when the peer resets while we cancel a pending read.
      closing = Promise.resolve(socket.close()).catch(() => {});
    } catch {
      /* already closed */
    }
  };

  const durationTimer = setTimeout(() => shutdown(RelayClose.CAP_EXCEEDED), limits.maxDurationMs);
  let idleTimer = setTimeout(() => shutdown(RelayClose.IDLE_TIMEOUT), limits.idleMs);
  const touch = () => {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => shutdown(RelayClose.IDLE_TIMEOUT), limits.idleMs);
  };

  const count = (n: number): boolean => {
    bytes += n;
    if (bytes > limits.maxBytes) {
      shutdown(RelayClose.CAP_EXCEEDED);
      return false;
    }
    return true;
  };

  // Bytes the proxy coalesced onto the end of its handshake reply. They are the
  // first bytes of the tunnel and go out before anything read afterwards.
  if (leftover.length > 0 && count(leftover.length)) {
    for (const piece of chunked(leftover)) ws.send(piece);
  }

  // Proxy -> client.
  const readLoop = (async () => {
    const reader = socket.readable.getReader();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (!value || value.length === 0) continue;
        if (!count(value.length)) return;
        touch();
        if (closed) return;
        for (const piece of chunked(value)) ws.send(piece);
      }
      shutdown(1000);
    } catch {
      shutdown(RelayClose.UPSTREAM_CLOSED);
    } finally {
      try {
        reader.releaseLock();
      } catch {
        /* stream already torn down */
      }
    }
  })();

  // Client -> proxy.
  ws.addEventListener("message", (event: MessageEvent) => {
    if (closed) return;
    const data = event.data;
    // After READY every frame is tunnel bytes. A text frame means the peer is
    // speaking a protocol we do not, which is a bug rather than data.
    if (typeof data === "string") {
      shutdown(RelayClose.UPSTREAM_CLOSED, "unexpected text frame");
      return;
    }
    const chunk = new Uint8Array(data as ArrayBuffer);
    if (!count(chunk.length)) return;
    touch();
    // Segmented so no single `writer.write()` call carries more than
    // MAX_SOCKET_CHUNK_BYTES - see the comment on that constant. Each piece
    // is still chained after the last, preserving the ordering the comment
    // at the top of this file requires.
    for (const piece of chunked(chunk)) {
      writeChain = writeChain.then(
        () => (closed ? undefined : writer.write(piece)),
        () => undefined
      ).catch(() => shutdown(RelayClose.UPSTREAM_CLOSED));
    }
  });

  ws.addEventListener("close", () => shutdown(1000));
  ws.addEventListener("error", () => shutdown(RelayClose.UPSTREAM_CLOSED));

  return readLoop.then(async () => {
    await closing;
    await writeChain;
  });
}
