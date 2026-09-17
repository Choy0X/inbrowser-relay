/**
 * SOCKS5 (RFC 1928) with optional username/password auth (RFC 1929).
 *
 * Two details here are easy to get wrong and hard to diagnose afterwards:
 *
 *  1. The request uses ATYP=0x03 (domain name) whenever the target is a
 *     hostname, so the *proxy* resolves DNS. Resolving here and sending an IP
 *     would route the request from the proxy's location to an address chosen by
 *     the relay's location, which for a CDN-fronted provider means the exit and
 *     the resolution disagree. It also leaks the intended hostname into the
 *     Worker's DNS path for no benefit.
 *  2. The reply's bound address is variable-length and must be parsed even
 *     though nothing uses its value, because it is the only way to know where
 *     the reply ends and the tunnel begins.
 */
import { HandshakeError, type HandshakeIo, type HandshakeResult } from "./types";
import type { DialRequest } from "../protocol";
import { parseIpv4, parseIpv6 } from "../dial";

const encoder = new TextEncoder();

const VERSION = 0x05;
const CMD_CONNECT = 0x01;
const RSV = 0x00;

const METHOD_NONE = 0x00;
const METHOD_USERPASS = 0x02;
const METHOD_UNACCEPTABLE = 0xff;

const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x03;
const ATYP_IPV6 = 0x04;

const REPLY_MESSAGES: Record<number, string> = {
  0x01: "The proxy reported a general failure.",
  0x02: "The proxy's rules do not allow this connection.",
  0x03: "The network is unreachable from the proxy.",
  0x04: "The host is unreachable from the proxy.",
  0x05: "The target refused the connection.",
  0x06: "The connection through the proxy timed out.",
  0x07: "The proxy does not support this command.",
  0x08: "The proxy does not support this address type.",
};

export async function socks5Handshake(io: HandshakeIo, dial: DialRequest): Promise<HandshakeResult> {
  const hasCredentials = Boolean(dial.username || dial.password);

  // 1. Greeting.
  const methods = hasCredentials ? [METHOD_NONE, METHOD_USERPASS] : [METHOD_NONE];
  await io.writer.write(new Uint8Array([VERSION, methods.length, ...methods]));

  const greeting = await io.reader.readExact(2);
  if (greeting[0] !== VERSION) throw new HandshakeError("The proxy did not answer as a SOCKS5 proxy.");
  const method = greeting[1];

  if (method === METHOD_UNACCEPTABLE) {
    throw new HandshakeError(
      hasCredentials
        ? "The proxy rejected every authentication method offered."
        : "The proxy requires a username and password."
    );
  }

  // 2. Username/password sub-negotiation.
  if (method === METHOD_USERPASS) {
    if (!hasCredentials) throw new HandshakeError("The proxy requires a username and password.");
    const user = encoder.encode(dial.username ?? "");
    const pass = encoder.encode(dial.password ?? "");
    if (user.length > 255 || pass.length > 255) {
      throw new HandshakeError("SOCKS5 credentials are limited to 255 bytes each.");
    }
    const auth = new Uint8Array(3 + user.length + pass.length);
    auth[0] = 0x01; // sub-negotiation version, not the SOCKS version
    auth[1] = user.length;
    auth.set(user, 2);
    auth[2 + user.length] = pass.length;
    auth.set(pass, 3 + user.length);
    await io.writer.write(auth);

    const authReply = await io.reader.readExact(2);
    if (authReply[1] !== 0x00) throw new HandshakeError("The proxy rejected these credentials.");
  } else if (method !== METHOD_NONE) {
    throw new HandshakeError(`The proxy asked for an unsupported authentication method (0x${method.toString(16)}).`);
  }

  // 3. Connect request.
  await io.writer.write(buildRequest(dial.target.host, dial.target.port));

  // 4. Reply.
  const head = await io.reader.readExact(4);
  if (head[0] !== VERSION) throw new HandshakeError("The proxy sent a malformed SOCKS5 reply.");
  const reply = head[1];
  if (reply !== 0x00) {
    throw new HandshakeError(REPLY_MESSAGES[reply] ?? `The proxy refused the connection (code ${reply}).`);
  }

  // The bound address is unused, but consuming it exactly is what separates the
  // reply from the first tunnel byte.
  const atyp = head[3];
  if (atyp === ATYP_IPV4) await io.reader.readExact(4);
  else if (atyp === ATYP_IPV6) await io.reader.readExact(16);
  else if (atyp === ATYP_DOMAIN) {
    const len = await io.reader.readExact(1);
    await io.reader.readExact(len[0]);
  } else {
    throw new HandshakeError(`The proxy replied with an unknown address type (0x${atyp.toString(16)}).`);
  }
  await io.reader.readExact(2); // bound port

  return { leftover: io.reader.takeLeftover() };
}

function buildRequest(host: string, port: number): Uint8Array {
  const header = [VERSION, CMD_CONNECT, RSV];

  const v4 = parseIpv4(host);
  if (v4 !== null) {
    return new Uint8Array([
      ...header,
      ATYP_IPV4,
      (v4 >>> 24) & 0xff,
      (v4 >>> 16) & 0xff,
      (v4 >>> 8) & 0xff,
      v4 & 0xff,
      (port >> 8) & 0xff,
      port & 0xff,
    ]);
  }

  const v6 = parseIpv6(host);
  if (v6 !== null) {
    return new Uint8Array([...header, ATYP_IPV6, ...v6, (port >> 8) & 0xff, port & 0xff]);
  }

  const name = encoder.encode(host);
  if (name.length > 255) throw new HandshakeError("The target hostname is too long for SOCKS5.");
  return new Uint8Array([...header, ATYP_DOMAIN, name.length, ...name, (port >> 8) & 0xff, port & 0xff]);
}
