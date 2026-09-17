/**
 * The shape every proxy handshake shares.
 *
 * A handshake is handed a `{ reader, writer }` pair and never a socket. That is
 * the single constraint that makes all of this testable: `verify:relay` stands
 * up real SOCKS and CONNECT servers on loopback, adapts their Node sockets with
 * `stream.Duplex.toWeb()`, and drives these exact production modules. If a
 * handshake ever reaches for `cloudflare:sockets` directly, the verify script
 * fails on a grep before it fails on anything subtler.
 */
import type { BufferedReader } from "../bufreader";
import type { DialRequest } from "../protocol";

export interface HandshakeIo {
  reader: BufferedReader;
  writer: WritableStreamDefaultWriter<Uint8Array>;
}

export interface HandshakeResult {
  /**
   * Bytes already read past the end of the handshake reply. These belong to the
   * tunnel and must be delivered before anything read afterwards.
   */
  leftover: Uint8Array;
}

/**
 * Thrown for a proxy that answered but refused. The message is shown to the
 * user, so it names what the proxy actually said rather than a generic failure.
 */
export class HandshakeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HandshakeError";
  }
}

export type Handshake = (io: HandshakeIo, dial: DialRequest) => Promise<HandshakeResult>;
