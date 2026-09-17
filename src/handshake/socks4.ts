/**
 * SOCKS4 and SOCKS4a.
 *
 * SOCKS4 can only express an IPv4 destination. SOCKS4a extends it with the
 * convention that an address of 0.0.0.x (x nonzero) is invalid as a real
 * address and therefore signals "a hostname follows the userid", which is how a
 * hostname target is sent. We always use 4a when the target is a name, because
 * resolving it here would put the relay's view of DNS in front of the proxy's -
 * the same reasoning as the ATYP choice in socks5.ts.
 *
 * There is no password field in this protocol at all. `dial.ts` rejects a
 * SOCKS4 dial that carries one rather than dropping it silently, so a user who
 * typed a password is told it cannot be used instead of wondering why auth
 * failed.
 */
import { HandshakeError, type HandshakeIo, type HandshakeResult } from "./types";
import type { DialRequest } from "../protocol";
import { parseIpv4, parseIpv6 } from "../dial";

const encoder = new TextEncoder();

const VERSION = 0x04;
const CMD_CONNECT = 0x01;

const REPLY_MESSAGES: Record<number, string> = {
  0x5b: "The proxy rejected or failed the connection.",
  0x5c: "The proxy could not reach an identd service on this client.",
  0x5d: "The proxy's identd check did not match the user id.",
};

export async function socks4Handshake(io: HandshakeIo, dial: DialRequest): Promise<HandshakeResult> {
  const { host, port } = dial.target;

  if (parseIpv6(host) !== null) {
    throw new HandshakeError("SOCKS4 cannot reach IPv6 addresses. Use SOCKS5 instead.");
  }

  const userid = encoder.encode(dial.username ?? "");
  if (userid.length > 255) throw new HandshakeError("The SOCKS4 user id is too long.");

  const v4 = parseIpv4(host);
  const parts: number[] = [VERSION, CMD_CONNECT, (port >> 8) & 0xff, port & 0xff];

  if (v4 !== null) {
    parts.push((v4 >>> 24) & 0xff, (v4 >>> 16) & 0xff, (v4 >>> 8) & 0xff, v4 & 0xff);
    parts.push(...userid, 0x00);
  } else {
    // SOCKS4a: an impossible address tells the proxy to read a hostname after the userid.
    parts.push(0, 0, 0, 1);
    parts.push(...userid, 0x00);
    const name = encoder.encode(host);
    if (name.length > 255) throw new HandshakeError("The target hostname is too long for SOCKS4a.");
    parts.push(...name, 0x00);
  }

  await io.writer.write(new Uint8Array(parts));

  // The reply is exactly 8 bytes: null, status, port, address. Unlike SOCKS5
  // there is nothing variable-length, so the tunnel starts at byte 9.
  const reply = await io.reader.readExact(8);
  if (reply[0] !== 0x00) throw new HandshakeError("The proxy sent a malformed SOCKS4 reply.");
  const status = reply[1];
  if (status !== 0x5a) {
    throw new HandshakeError(REPLY_MESSAGES[status] ?? `The proxy refused the connection (code 0x${status.toString(16)}).`);
  }

  return { leftover: io.reader.takeLeftover() };
}
