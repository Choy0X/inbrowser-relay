/**
 * Dial validation: what the relay is willing to connect to, and to what.
 *
 * Pure - no `cloudflare:sockets`, nothing but string and number work - so
 * `npm run verify:relay` can drive it directly in Node. That is enforced: the
 * verify script greps this file for the sockets import and fails if it appears.
 *
 * Scope of what this can actually guarantee, stated plainly because it is easy
 * to over-claim: the Worker runtime has no DNS resolver, so a *public hostname
 * that resolves to a private address* passes every check below. The platform's
 * own `connect()` restrictions (it refuses localhost, private ranges and
 * Cloudflare IP ranges) are what cover that case, not this file. Everything
 * here is about literal addresses and obviously-local names, where the classic
 * bypass is writing 127.0.0.1 in one of its several other legal spellings.
 */
import { RelayClose, type DialProtocol, type DialRequest } from "./protocol";

/** Targets are HTTP endpoints. Restricting to these two is what stops the relay being a general TCP proxy. */
export const ALLOWED_TARGET_PORTS = new Set([80, 443]);

/** Ports whose abuse generates the complaints that get a Cloudflare account terminated. */
export const DENIED_PROXY_PORTS = new Set([22, 23, 25, 465, 587, 6667]);

const VALID_PROTOCOLS = new Set<DialProtocol>(["http", "https", "socks5", "socks4"]);

const LOCAL_HOST_SUFFIXES = [".localhost", ".local", ".internal", ".home.arpa"];

export interface DialRejection {
  code: number;
  message: string;
}

/**
 * Parses an IPv4 literal in every form inet_aton accepts, because `2130706433`
 * and `0x7f.1` are both 127.0.0.1 and a dotted-quad-only check waves them
 * straight through. Returns the address as an unsigned 32-bit number, or null
 * if the string is not an IPv4 literal at all.
 */
export function parseIpv4(host: string): number | null {
  const parts = host.split(".");
  if (parts.length === 0 || parts.length > 4) return null;

  const values: number[] = [];
  for (const part of parts) {
    if (part.length === 0) return null;
    let value: number;
    if (/^0[xX][0-9a-fA-F]+$/.test(part)) value = parseInt(part.slice(2), 16);
    else if (/^0[0-7]+$/.test(part)) value = parseInt(part.slice(1), 8);
    else if (/^[0-9]+$/.test(part)) value = parseInt(part, 10);
    else return null;
    if (!Number.isFinite(value) || value < 0) return null;
    values.push(value);
  }

  // inet_aton: the final part absorbs all remaining bytes, so a.b is a.(24-bit),
  // a.b.c is a.b.(16-bit), and a bare number is the whole 32-bit address.
  const last = values[values.length - 1];
  const leading = values.slice(0, -1);
  if (leading.some((v) => v > 255)) return null;
  const remainingBytes = 4 - leading.length;
  if (last >= 2 ** (8 * remainingBytes)) return null;

  let addr = 0;
  for (const v of leading) addr = addr * 256 + v;
  addr = addr * 2 ** (8 * remainingBytes) + last;
  return addr >>> 0;
}

function inCidr(addr: number, base: string, bits: number): boolean {
  const baseAddr = parseIpv4(base);
  if (baseAddr === null) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return ((addr & mask) >>> 0) === ((baseAddr & mask) >>> 0);
}

/** RFC1918 and friends, plus the ranges that are simply not valid destinations. */
export function isPrivateIpv4(addr: number): boolean {
  return (
    inCidr(addr, "0.0.0.0", 8) ||
    inCidr(addr, "10.0.0.0", 8) ||
    inCidr(addr, "100.64.0.0", 10) ||
    inCidr(addr, "127.0.0.0", 8) ||
    inCidr(addr, "169.254.0.0", 16) ||
    inCidr(addr, "172.16.0.0", 12) ||
    inCidr(addr, "192.0.0.0", 24) ||
    inCidr(addr, "192.168.0.0", 16) ||
    inCidr(addr, "198.18.0.0", 15) ||
    inCidr(addr, "224.0.0.0", 4) ||
    inCidr(addr, "240.0.0.0", 4)
  );
}

/**
 * Expands an IPv6 literal to its 16 bytes, or null if it is not one. Accepts the
 * bracketed form and the `::ffff:a.b.c.d` v4-mapped tail.
 */
export function parseIpv6(host: string): Uint8Array | null {
  let text = host.trim();
  if (text.startsWith("[") && text.endsWith("]")) text = text.slice(1, -1);
  const zone = text.indexOf("%");
  if (zone !== -1) text = text.slice(0, zone);
  if (!text.includes(":")) return null;

  const [head, tail, ...rest] = text.split("::");
  if (rest.length > 0) return null;

  const expand = (chunk: string): number[] | null => {
    if (chunk === "") return [];
    const groups: number[] = [];
    for (const piece of chunk.split(":")) {
      if (piece.includes(".")) {
        const v4 = parseIpv4(piece);
        if (v4 === null) return null;
        groups.push((v4 >>> 16) & 0xffff, v4 & 0xffff);
        continue;
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(piece)) return null;
      groups.push(parseInt(piece, 16));
    }
    return groups;
  };

  const headGroups = expand(head);
  if (headGroups === null) return null;
  const tailGroups = tail === undefined ? null : expand(tail);
  if (tail !== undefined && tailGroups === null) return null;

  let groups: number[];
  if (tail === undefined) {
    if (headGroups.length !== 8) return null;
    groups = headGroups;
  } else {
    const fill = 8 - headGroups.length - (tailGroups as number[]).length;
    if (fill < 1) return null;
    groups = [...headGroups, ...new Array(fill).fill(0), ...(tailGroups as number[])];
  }

  const bytes = new Uint8Array(16);
  groups.forEach((g, i) => {
    bytes[i * 2] = (g >> 8) & 0xff;
    bytes[i * 2 + 1] = g & 0xff;
  });
  return bytes;
}

export function isPrivateIpv6(bytes: Uint8Array): boolean {
  const isUnspecified = bytes.every((b) => b === 0);
  const isLoopback = bytes.slice(0, 15).every((b) => b === 0) && bytes[15] === 1;
  if (isUnspecified || isLoopback) return true;
  // Unique local fc00::/7 and link-local fe80::/10.
  if ((bytes[0] & 0xfe) === 0xfc) return true;
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) return true;
  // v4-mapped ::ffff:0:0/96 - unwrap and judge the IPv4 address on its own terms.
  const v4Mapped = bytes.slice(0, 10).every((b) => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff;
  if (v4Mapped) {
    const addr = ((bytes[12] << 24) | (bytes[13] << 16) | (bytes[14] << 8) | bytes[15]) >>> 0;
    return isPrivateIpv4(addr);
  }
  return false;
}

/** True when a host must not be dialled: a local name, or a literal in a private range. */
export function isBlockedHost(host: string): boolean {
  const lower = host.trim().toLowerCase().replace(/\.$/, "");
  if (lower.length === 0) return true;
  if (lower === "localhost") return true;
  if (LOCAL_HOST_SUFFIXES.some((suffix) => lower.endsWith(suffix))) return true;

  const v4 = parseIpv4(lower);
  if (v4 !== null) return isPrivateIpv4(v4);

  const v6 = parseIpv6(lower);
  if (v6 !== null) return isPrivateIpv6(v6);

  return false;
}

function isValidPort(port: unknown): port is number {
  return typeof port === "number" && Number.isInteger(port) && port >= 1 && port <= 65535;
}

function isValidHostname(host: unknown): host is string {
  return typeof host === "string" && host.length > 0 && host.length <= 253 && !/[\s/@\\]/.test(host);
}

/**
 * Validates a decrypted dial. Returns null when the dial is acceptable, or the
 * close code plus a message that is safe to show the user.
 */
export function validateDial(dial: DialRequest): DialRejection | null {
  if (!VALID_PROTOCOLS.has(dial.protocol)) {
    return { code: RelayClose.DIAL_REJECTED, message: `Unknown proxy protocol "${String(dial.protocol)}".` };
  }
  if (!isValidHostname(dial.host)) {
    return { code: RelayClose.DIAL_REJECTED, message: "The proxy host is missing or malformed." };
  }
  if (!isValidPort(dial.port)) {
    return { code: RelayClose.DIAL_REJECTED, message: "The proxy port must be between 1 and 65535." };
  }
  if (DENIED_PROXY_PORTS.has(dial.port)) {
    return { code: RelayClose.DIAL_REJECTED, message: `The relay does not connect to proxies on port ${dial.port}.` };
  }
  if (isBlockedHost(dial.host)) {
    return { code: RelayClose.DIAL_REJECTED, message: "The proxy address is a local or reserved address." };
  }
  // SOCKS4 has a userid field and no password field on the wire. Silently
  // dropping a password the user typed would look like it had been sent.
  if (dial.protocol === "socks4" && dial.password) {
    return { code: RelayClose.DIAL_REJECTED, message: "SOCKS4 does not support passwords. Use SOCKS5 instead." };
  }

  const target = dial.target;
  if (!target || !isValidHostname(target.host)) {
    return { code: RelayClose.TARGET_NOT_ALLOWED, message: "The target host is missing or malformed." };
  }
  if (!isValidPort(target.port) || !ALLOWED_TARGET_PORTS.has(target.port)) {
    return { code: RelayClose.TARGET_NOT_ALLOWED, message: "The relay only connects to targets on port 80 or 443." };
  }
  if (isBlockedHost(target.host)) {
    return { code: RelayClose.TARGET_NOT_ALLOWED, message: "The target address is a local or reserved address." };
  }
  // The bucket is inside the seal, so a malformed one means the relay has a
  // bug rather than that somebody is probing - but it is used as a rate-limit
  // key, and an unbounded or oddly-shaped key is not something to hand to a
  // binding unchecked.
  if (dial.bucket !== undefined && !isValidBucket(dial.bucket)) {
    return { code: RelayClose.DIAL_REJECTED, message: "The dial carried a malformed rate-limit key." };
  }
  return null;
}

/** base64url, and short. deriveBucket on the relay side emits 22 characters. */
function isValidBucket(value: unknown): boolean {
  return typeof value === "string" && value.length > 0 && value.length <= 64 && /^[A-Za-z0-9_-]+$/.test(value);
}

/**
 * Whether a browser's `Origin` header is one this relay will serve.
 *
 * WHY THIS IS NOT A STRING COMPARISON ANY MORE. `ALLOWED_ORIGINS` used to be
 * matched with `Array.includes`, so every entry had to be a full origin spelled
 * exactly, scheme included. Writing the obvious thing in wrangler.toml -
 * `*.inbrowser.tech` - then silently rejected every real request, because no
 * `Origin` header is ever literally that string. A config value that looks
 * right and blocks everything is worse than no config value.
 *
 * Three forms are accepted, and a pattern is compared against the parsed host
 * rather than the raw header so trailing slashes and case cannot matter:
 *
 *   `https://inbrowser.tech`  full origin, exact, scheme included
 *   `inbrowser.tech`          bare host, any scheme
 *   `*.inbrowser.tech`        that host AND anything beneath it
 *
 * **The wildcard deliberately includes the apex.** Standard wildcard
 * certificate semantics exclude it - `*.example.com` does not cover
 * `example.com` - but the app is served from the apex, so the strict reading
 * would reject production while looking correct in the config. The surprising
 * behaviour is worth one comment; a relay that 403s its own app is not.
 *
 * The leading dot in the suffix test is load-bearing: without it
 * `evilinbrowser.tech` would match `*.inbrowser.tech`.
 */
export function isOriginAllowed(origin: string, patterns: string[]): boolean {
  let host: string;
  let scheme: string;
  try {
    const parsed = new URL(origin);
    host = parsed.hostname.toLowerCase();
    scheme = parsed.protocol.toLowerCase();
  } catch {
    // `Origin: null`, which sandboxed iframes and some privacy tools send, and
    // anything malformed. Neither is the app.
    return false;
  }
  if (!host) return false;

  return patterns.some((raw) => {
    const pattern = raw.trim().toLowerCase();
    if (!pattern) return false;

    if (pattern.includes("://")) return `${scheme}//${host}` === pattern;

    if (pattern.startsWith("*.")) {
      const apex = pattern.slice(2);
      return apex.length > 0 && (host === apex || host.endsWith(`.${apex}`));
    }

    return host === pattern;
  });
}
