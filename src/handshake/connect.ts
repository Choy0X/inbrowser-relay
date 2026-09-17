/**
 * HTTP CONNECT, which serves both the `http` and `https` proxy protocols.
 *
 * The bytes are identical for the two; the only difference is whether the
 * socket underneath was opened with TLS, and that decision belongs to the
 * caller (index.ts), not here. That split is the whole reason HTTPS proxies are
 * possible at all: the outer TLS is the Worker's, the inner TLS is the VPS's,
 * and neither runtime is ever asked to nest one inside the other.
 */
import { HandshakeError, type HandshakeIo, type HandshakeResult } from "./types";
import type { DialRequest } from "../protocol";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const CRLFCRLF = new Uint8Array([0x0d, 0x0a, 0x0d, 0x0a]);
const MAX_REPLY_BYTES = 8192;

function basicAuth(username: string, password: string): string {
  const raw = `${username}:${password}`;
  // btoa is latin1-only; encode to UTF-8 bytes first so non-ASCII credentials
  // survive rather than throwing an InvalidCharacterError.
  const bytes = encoder.encode(raw);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export async function connectHandshake(io: HandshakeIo, dial: DialRequest): Promise<HandshakeResult> {
  const authority = `${dial.target.host}:${dial.target.port}`;
  const lines = [`CONNECT ${authority} HTTP/1.1`, `Host: ${authority}`];
  const hasCredentials = Boolean(dial.username || dial.password);
  if (hasCredentials) {
    lines.push(`Proxy-Authorization: Basic ${basicAuth(dial.username ?? "", dial.password ?? "")}`);
  }
  lines.push("Proxy-Connection: keep-alive", "", "");

  await io.writer.write(encoder.encode(lines.join("\r\n")));

  const head = await io.reader.readUntil(CRLFCRLF, MAX_REPLY_BYTES);
  const text = decoder.decode(head);
  const statusLine = text.split("\r\n", 1)[0] ?? "";
  const match = /^HTTP\/\d(?:\.\d)?\s+(\d{3})\s*(.*)$/.exec(statusLine);
  if (!match) {
    throw new HandshakeError("The proxy did not reply with a valid HTTP response.");
  }

  const status = Number(match[1]);
  const reason = match[2].trim();

  // Any 2xx opens the tunnel. Not every proxy answers exactly 200 - some return
  // 201 - and treating a successful CONNECT as a failure over the last digit
  // would be a confusing way to lose a working proxy.
  if (status >= 200 && status < 300) {
    return { leftover: io.reader.takeLeftover() };
  }

  if (status === 407) {
    throw new HandshakeError(
      hasCredentials
        ? "The proxy rejected these credentials."
        : "The proxy requires a username and password."
    );
  }
  if (status === 403) throw new HandshakeError("The proxy refused to connect to that address.");
  if (status === 502 || status === 504) throw new HandshakeError("The proxy could not reach the target.");
  throw new HandshakeError(`The proxy refused the connection: ${status}${reason ? ` ${reason}` : ""}.`);
}
