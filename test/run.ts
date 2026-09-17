/**
 * The relay Worker's test suite. Run with `npm test`. Needs no network.
 *
 * Everything here drives the production modules in `src/`, not reimplementations
 * of them. That is possible because of one layering rule, which this suite also
 * enforces: `cloudflare:sockets` is imported in exactly one file (`src/index.ts`)
 * and every handshake takes a `{ reader, writer }` pair rather than a `Socket`.
 * So the handshakes can be driven against real loopback SOCKS and CONNECT
 * servers under plain Node, using `stream.Duplex.toWeb()` in place of the
 * Workers socket API.
 *
 * These tests used to live in the InBrowser app repository, where the Worker was
 * a subdirectory. When it moved out, the handshake, dial-policy and crypto
 * coverage came with it - the code is here, so the tests are here. What the app
 * repo keeps is what it still owns: the envelope, the tunnel, and its own end of
 * the wire format.
 *
 * The one thing that spans the boundary is `src/conformance.ts`, a frozen sealed
 * frame that both repositories must be able to open. See that file.
 */
import net from "node:net";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Duplex } from "node:stream";

import { BufferedReader } from "../src/bufreader";
import { deriveDialKey, newNonce, openDial, sealDial } from "../src/crypto";
import {
  ALLOWED_TARGET_PORTS,
  DENIED_PROXY_PORTS,
  isBlockedHost,
  isOriginAllowed,
  parseIpv4,
  validateDial,
} from "../src/dial";
import { connectHandshake } from "../src/handshake/connect";
import { socks4Handshake } from "../src/handshake/socks4";
import { socks5Handshake } from "../src/handshake/socks5";
import { HandshakeError } from "../src/handshake/types";
import { decodeControlFrame, encodeErrorFrame, RelayClose, type DialRequest } from "../src/protocol";
import { EXPECTED_DIAL, VECTOR_SECRET, vectorFrame } from "../src/conformance";
import { pipe } from "../src/pipe";

import { startConnectProxy, startSocks4, startSocks5, type TestProxy } from "./proxyServers";

const ROOT = process.cwd();
const SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef";

let failures = 0;
let checks = 0;

function check(label: string, ok: boolean, detail = ""): void {
  checks++;
  if (ok) console.log(`  ok   ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}${detail ? ` - ${detail}` : ""}`);
  }
}

function section(title: string): void {
  console.log(`\n${title}`);
}

async function driveHandshake(
  proxy: TestProxy,
  dial: DialRequest,
  handshake: typeof connectHandshake
): Promise<{ leftover: Uint8Array; socket: net.Socket }> {
  const socket = net.connect(proxy.port, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  });
  const web = Duplex.toWeb(socket);
  const reader = (web.readable as ReadableStream<Uint8Array>).getReader();
  const writer = (web.writable as WritableStream<Uint8Array>).getWriter();
  const result = await handshake({ reader: new BufferedReader(reader), writer }, dial);
  return { leftover: result.leftover, socket };
}

function dialFor(overrides: Partial<DialRequest> = {}): DialRequest {
  return {
    ts: Date.now(),
    nonce: newNonce(),
    protocol: "socks5",
    host: "127.0.0.1",
    port: 1080,
    target: { host: "example.test", port: 80 },
    ...overrides,
  };
}

async function expectThrows(fn: () => Promise<unknown>): Promise<Error | null> {
  try {
    await fn();
    return null;
  } catch (err) {
    return err instanceof Error ? err : new Error(String(err));
  }
}

// ----------------------------------------------------------- 1. handshakes

async function testHandshakes(): Promise<void> {
  section("Handshakes against real loopback proxies");

  {
    const proxy = await startSocks5("noauth");
    const dial = dialFor({ host: "127.0.0.1", port: proxy.port, target: { host: "abc.test", port: 80 } });
    const { socket } = await driveHandshake(proxy, dial, socks5Handshake);
    const sent = proxy.received();

    check("socks5 greeting offers only no-auth when uncredentialed", sent[0] === 0x05 && sent[1] === 1 && sent[2] === 0x00);
    const req = sent.subarray(3);
    check(
      "socks5 uses ATYP=domain so the proxy resolves DNS",
      req[0] === 0x05 && req[1] === 0x01 && req[2] === 0x00 && req[3] === 0x03,
      req.subarray(0, 4).toString("hex")
    );
    check("socks5 length-prefixes the hostname", req[4] === "abc.test".length);
    check("socks5 sends the hostname verbatim", req.subarray(5, 5 + 8).toString("utf8") === "abc.test");
    check("socks5 writes the port big-endian", req.readUInt16BE(5 + 8) === 80);

    socket.destroy();
    await proxy.close();
  }

  {
    const proxy = await startSocks5("noauth");
    const dial = dialFor({ host: "127.0.0.1", port: proxy.port, target: { host: "93.184.216.34", port: 443 } });
    const { socket } = await driveHandshake(proxy, dial, socks5Handshake);
    const req = proxy.received().subarray(3);
    check(
      "socks5 uses ATYP=IPv4 for a literal address",
      req[3] === 0x01 && req[4] === 93 && req[5] === 184 && req[6] === 216 && req[7] === 34
    );
    socket.destroy();
    await proxy.close();
  }

  {
    const proxy = await startSocks5("userpass");
    const dial = dialFor({ host: "127.0.0.1", port: proxy.port, username: "u", password: "pw" });
    const { socket } = await driveHandshake(proxy, dial, socks5Handshake);
    const sent = proxy.received();
    check("socks5 offers user/pass when credentialed", sent[1] === 2 && sent[3] === 0x02);
    const auth = sent.subarray(4);
    check(
      "socks5 sub-negotiation is version 1 with length-prefixed fields",
      auth[0] === 0x01 && auth[1] === 1 && auth.subarray(2, 3).toString() === "u" && auth[3] === 2
    );
    socket.destroy();
    await proxy.close();
  }

  for (const [mode, expected] of [
    ["reject-auth", "rejected these credentials"],
    ["no-methods", "requires a username and password"],
    ["rep5", "refused the connection"],
  ] as const) {
    const proxy = await startSocks5(mode);
    const dial = dialFor({
      host: "127.0.0.1",
      port: proxy.port,
      ...(mode === "reject-auth" ? { username: "u", password: "bad" } : {}),
    });
    const err = await expectThrows(() => driveHandshake(proxy, dial, socks5Handshake));
    check(
      `socks5 ${mode} maps to a specific message`,
      err instanceof HandshakeError && err.message.includes(expected),
      err?.message
    );
    await proxy.close();
  }

  {
    const proxy = await startSocks5("ipv6-bnd");
    const dial = dialFor({ host: "127.0.0.1", port: proxy.port });
    const err = await expectThrows(() => driveHandshake(proxy, dial, socks5Handshake));
    check("socks5 parses an IPv6 bound address without desyncing", err === null, err?.message);
    await proxy.close();
  }

  {
    const proxy = await startSocks4("granted");
    const dial = dialFor({
      protocol: "socks4",
      host: "127.0.0.1",
      port: proxy.port,
      username: "ident",
      target: { host: "abc.test", port: 80 },
    });
    const { socket } = await driveHandshake(proxy, dial, socks4Handshake);
    const sent = proxy.received();
    check("socks4 sends version 4 connect", sent[0] === 0x04 && sent[1] === 0x01);
    check("socks4 writes the port big-endian", sent.readUInt16BE(2) === 80);
    check(
      "socks4a signals a hostname with the 0.0.0.x sentinel",
      sent[4] === 0 && sent[5] === 0 && sent[6] === 0 && sent[7] !== 0
    );
    check("socks4a appends a null-terminated hostname after the user id", sent.includes(Buffer.from("abc.test\0")));
    socket.destroy();
    await proxy.close();
  }

  for (const [mode, expected] of [
    ["rejected", "rejected or failed"],
    ["identd", "identd"],
  ] as const) {
    const proxy = await startSocks4(mode);
    const dial = dialFor({ protocol: "socks4", host: "127.0.0.1", port: proxy.port });
    const err = await expectThrows(() => driveHandshake(proxy, dial, socks4Handshake));
    check(`socks4 ${mode} maps to a specific message`, err?.message.includes(expected) ?? false, err?.message);
    await proxy.close();
  }

  {
    const proxy = await startConnectProxy("ok");
    const dial = dialFor({ protocol: "http", host: "127.0.0.1", port: proxy.port, target: { host: "abc.test", port: 443 } });
    const { socket } = await driveHandshake(proxy, dial, connectHandshake);
    const sent = proxy.received().toString("utf8");
    check("CONNECT uses authority-form with the target port", sent.startsWith("CONNECT abc.test:443 HTTP/1.1\r\n"));
    check("CONNECT sends a matching Host header", sent.includes("Host: abc.test:443\r\n"));
    check("CONNECT sends no Proxy-Authorization when uncredentialed", !sent.includes("Proxy-Authorization"));
    socket.destroy();
    await proxy.close();
  }

  {
    const proxy = await startConnectProxy("ok");
    const dial = dialFor({ protocol: "http", host: "127.0.0.1", port: proxy.port, username: "u", password: "p" });
    const { socket } = await driveHandshake(proxy, dial, connectHandshake);
    const sent = proxy.received().toString("utf8");
    check(
      "CONNECT sends Basic credentials when given",
      sent.includes(`Proxy-Authorization: Basic ${Buffer.from("u:p").toString("base64")}`)
    );
    socket.destroy();
    await proxy.close();
  }

  {
    const proxy = await startConnectProxy("ok-201");
    const dial = dialFor({ protocol: "http", host: "127.0.0.1", port: proxy.port });
    const err = await expectThrows(() => driveHandshake(proxy, dial, connectHandshake));
    check("CONNECT accepts any 2xx, not only 200", err === null, err?.message);
    await proxy.close();
  }

  for (const [mode, expected] of [
    ["auth-required", "requires a username and password"],
    ["bad-gateway", "could not reach the target"],
  ] as const) {
    const proxy = await startConnectProxy(mode);
    const dial = dialFor({ protocol: "http", host: "127.0.0.1", port: proxy.port });
    const err = await expectThrows(() => driveHandshake(proxy, dial, connectHandshake));
    check(`CONNECT ${mode} maps to a specific message`, err?.message.includes(expected) ?? false, err?.message);
    await proxy.close();
  }

  {
    const proxy = await startConnectProxy("coalesce");
    const dial = dialFor({ protocol: "http", host: "127.0.0.1", port: proxy.port });
    const { leftover, socket } = await driveHandshake(proxy, dial, connectHandshake);
    check(
      "a handshake reply coalesced with tunnel bytes returns them as leftover",
      Buffer.from(leftover).toString("utf8") === "LEFTOVER",
      JSON.stringify(Buffer.from(leftover).toString("utf8"))
    );
    socket.destroy();
    await proxy.close();
  }
}

// ---------------------------------------------------------- 2. dial policy

function testDialPolicy(): void {
  section("Dial policy");

  for (const spelling of ["127.0.0.1", "2130706433", "0x7f.0.0.1", "0x7f000001", "017700000001", "127.1"]) {
    check(`blocks loopback written as ${spelling}`, isBlockedHost(spelling), String(parseIpv4(spelling)));
  }

  for (const host of [
    "10.1.2.3",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "0.0.0.0",
    "224.0.0.1",
    "::1",
    "[::1]",
    "fd00::1",
    "fe80::1",
    "::ffff:127.0.0.1",
    "localhost",
    "foo.localhost",
    "db.internal",
    "printer.local",
  ]) {
    check(`blocks ${host}`, isBlockedHost(host));
  }

  for (const host of ["example.com", "8.8.8.8", "172.32.0.1", "2001:4860:4860::8888", "api.openai.com"]) {
    check(`allows ${host}`, !isBlockedHost(host));
  }

  check("172.15.x is public, 172.16.x is not", !isBlockedHost("172.15.0.1") && isBlockedHost("172.16.0.1"));
  check(
    "target ports are limited to 80 and 443",
    ALLOWED_TARGET_PORTS.has(80) && ALLOWED_TARGET_PORTS.has(443) && ALLOWED_TARGET_PORTS.size === 2
  );
  check("SMTP and SSH proxy ports are denied", DENIED_PROXY_PORTS.has(25) && DENIED_PROXY_PORTS.has(22));
  check(
    "a good dial passes",
    validateDial(dialFor({ host: "proxy.example.com", target: { host: "api.openai.com", port: 443 } })) === null
  );

  const cases: [string, Partial<DialRequest>, number][] = [
    ["a target on a non-HTTP port", { host: "proxy.example.com", target: { host: "api.openai.com", port: 8080 } }, RelayClose.TARGET_NOT_ALLOWED],
    ["a private target", { host: "proxy.example.com", target: { host: "169.254.169.254", port: 80 } }, RelayClose.TARGET_NOT_ALLOWED],
    ["a private proxy", { host: "10.0.0.1", target: { host: "api.openai.com", port: 443 } }, RelayClose.DIAL_REJECTED],
    ["a denied proxy port", { host: "proxy.example.com", port: 25, target: { host: "api.openai.com", port: 443 } }, RelayClose.DIAL_REJECTED],
    ["an out-of-range proxy port", { host: "proxy.example.com", port: 70000, target: { host: "api.openai.com", port: 443 } }, RelayClose.DIAL_REJECTED],
    ["socks4 carrying a password", { protocol: "socks4", host: "proxy.example.com", password: "x", target: { host: "api.openai.com", port: 443 } }, RelayClose.DIAL_REJECTED],
    ["an unknown protocol", { protocol: "gopher" as DialRequest["protocol"], host: "proxy.example.com", target: { host: "api.openai.com", port: 443 } }, RelayClose.DIAL_REJECTED],
  ];
  for (const [label, overrides, code] of cases) {
    const rejection = validateDial(dialFor(overrides));
    check(`rejects ${label}`, rejection?.code === code, rejection ? `code ${rejection.code}` : "accepted");
  }

  check(
    "the socks4 password rejection names SOCKS5 as the fix",
    validateDial(dialFor({ protocol: "socks4", host: "p.example.com", password: "x" }))?.message.includes("SOCKS5") ?? false
  );

  section("Origin policy");

  // The deployed value. It has to admit the apex, because that is where the app
  // is actually served from - a wildcard read strictly would 403 production.
  const deployed = ["*.inbrowser.tech"];
  for (const origin of [
    "https://inbrowser.tech",
    "https://www.inbrowser.tech",
    "https://staging.inbrowser.tech",
    "https://deep.nested.inbrowser.tech",
  ]) {
    check(`*.inbrowser.tech admits ${origin}`, isOriginAllowed(origin, deployed));
  }

  // The suffix trap: without the leading dot in the endsWith test, every one of
  // these would be admitted.
  for (const origin of [
    "https://evilinbrowser.tech",
    "https://inbrowser.tech.evil.com",
    "https://notinbrowser.tech",
    "https://inbrowser.technology",
  ]) {
    check(`*.inbrowser.tech rejects ${origin}`, !isOriginAllowed(origin, deployed));
  }

  check("a null Origin is rejected", !isOriginAllowed("null", deployed));
  check("a malformed Origin is rejected", !isOriginAllowed("not a url", deployed));
  check(
    "a trailing slash does not defeat the match",
    isOriginAllowed("https://inbrowser.tech/", deployed)
  );
  check(
    "case does not defeat the match",
    isOriginAllowed("HTTPS://InBrowser.Tech", deployed)
  );

  check(
    "a full-origin pattern pins the scheme",
    isOriginAllowed("https://inbrowser.tech", ["https://inbrowser.tech"]) &&
      !isOriginAllowed("http://inbrowser.tech", ["https://inbrowser.tech"])
  );
  check(
    "a bare-host pattern accepts any scheme",
    isOriginAllowed("http://localhost", ["localhost"]) &&
      isOriginAllowed("https://localhost", ["localhost"])
  );
  check(
    "a bare-host pattern does not match subdomains",
    !isOriginAllowed("https://www.inbrowser.tech", ["inbrowser.tech"])
  );
  check("an empty pattern list matches nothing", !isOriginAllowed("https://inbrowser.tech", []));
  check("a bare '*.' pattern matches nothing", !isOriginAllowed("https://inbrowser.tech", ["*."]));
}

// --------------------------------------------------------------- 3. crypto

async function testCrypto(): Promise<void> {
  section("Dial sealing");

  const key = await deriveDialKey(SECRET);
  const dial = dialFor({ username: "user", password: "s3cret" });
  const frame = await sealDial(key, dial);

  const opened = await openDial(key, frame);
  check("a sealed dial round-trips", opened.host === dial.host && opened.password === "s3cret");
  check(
    "credentials are not readable in the sealed frame",
    !Buffer.from(frame).toString("utf8").includes("s3cret") && !Buffer.from(frame).toString("latin1").includes("s3cret")
  );

  const otherKey = await deriveDialKey("ffffffffffffffffffffffffffffffffffffffffffffffff");
  check("a frame sealed under another secret does not open", (await expectThrows(() => openDial(otherKey, frame))) !== null);

  const tampered = new Uint8Array(frame);
  tampered[tampered.length - 1] ^= 0xff;
  check("a tampered tag is rejected", (await expectThrows(() => openDial(key, tampered))) !== null);

  const stale = await sealDial(key, dialFor({ ts: Date.now() - 120_000 }));
  check("a stale dial is rejected", (await expectThrows(() => openDial(key, stale))) !== null);

  const future = await sealDial(key, dialFor({ ts: Date.now() + 120_000 }));
  check("a far-future dial is rejected too", (await expectThrows(() => openDial(key, future))) !== null);

  check("a short secret is refused outright", (await expectThrows(() => deriveDialKey("tooshort"))) !== null);

  const err = decodeControlFrame(encodeErrorFrame(RelayClose.HANDSHAKE_FAILED, "nope"));
  check("error frames round-trip", err.kind === "error" && err.code === RelayClose.HANDSHAKE_FAILED && err.message === "nope");

  const long = decodeControlFrame(encodeErrorFrame(RelayClose.DIAL_REJECTED, "x".repeat(400)));
  check(
    "an error frame carries a message longer than a close reason allows",
    long.kind === "error" && long.message.length === 400
  );
}

// --------------------------------------------------------- 4. conformance

async function testConformance(): Promise<void> {
  section("Cross-repo wire-format conformance");

  const key = await deriveDialKey(VECTOR_SECRET);
  const opened = await openDial(key, vectorFrame(), EXPECTED_DIAL.ts);

  check(
    "the frozen vector opens with this build's key derivation",
    opened.host === EXPECTED_DIAL.host && opened.port === EXPECTED_DIAL.port,
    "the two repositories disagree about HKDF or AES parameters - find which side changed"
  );
  check("the vector's credentials survive intact", opened.username === EXPECTED_DIAL.username && opened.password === EXPECTED_DIAL.password);
  check("the vector's target survives intact", opened.target.host === EXPECTED_DIAL.target.host && opened.target.port === EXPECTED_DIAL.target.port);
  check("the vector's protocol and nonce survive intact", opened.protocol === EXPECTED_DIAL.protocol && opened.nonce === EXPECTED_DIAL.nonce);
}

// ------------------------------------------------------------- 5. layering

function testLayering(): void {
  section("Layering and privacy invariants");

  const pure = [
    "src/protocol.ts",
    "src/crypto.ts",
    "src/dial.ts",
    "src/bufreader.ts",
    "src/pipe.ts",
    "src/conformance.ts",
    "src/handshake/connect.ts",
    "src/handshake/socks4.ts",
    "src/handshake/socks5.ts",
    "src/handshake/types.ts",
  ];
  // A real import, not a mention - several of these files discuss the rule in
  // their own comments, and a substring search flags them for complying with it.
  const SOCKETS_IMPORT = /^\s*import[^;]*["']cloudflare:sockets["']/m;
  for (const file of pure) {
    check(`${file} does not import cloudflare:sockets`, !SOCKETS_IMPORT.test(readFileSync(join(ROOT, file), "utf8")));
  }

  const entry = readFileSync(join(ROOT, "src/index.ts"), "utf8");
  check("src/index.ts is the one file that does", entry.includes('from "cloudflare:sockets"'));

  // The relay's privacy claim rests on this. See the header of src/index.ts.
  const logsRequestData = /console\.(log|info|warn|error)\([^)]*\b(dial|target|host|password|username|proxy)\b/i.test(entry);
  check("src/index.ts logs no dial field", !logsRequestData);

  const wrangler = readFileSync(join(ROOT, "wrangler.toml"), "utf8");
  check("logpush is disabled", /logpush\s*=\s*false/.test(wrangler));
}

// ------------------------------------------------------------------- main

async function testPipeShutdown(): Promise<void> {
  section("Tunnel shutdown");
  const unhandled: unknown[] = [];
  const onUnhandled = (error: unknown) => { unhandled.push(error); };
  process.on("unhandledRejection", onUnhandled);
  try {
    const ws = new EventTarget();
    let wsCloses = 0;
    Object.assign(ws, { send() {}, close() { wsCloses++; } });
    let tcpCloses = 0;
    let source!: ReadableStreamDefaultController<Uint8Array>;
    const socket = {
      readable: new ReadableStream<Uint8Array>({ start(controller) { source = controller; } }),
      writable: new WritableStream<Uint8Array>(),
      close() {
        tcpCloses++;
        source.error(new Error("peer reset"));
        return Promise.reject(new Error("TCP close rejected"));
      },
    };
    pipe(ws as unknown as WebSocket, socket, new Uint8Array());
    ws.dispatchEvent(new Event("close"));
    await new Promise(resolve => setTimeout(resolve,20));
    check("client close tears down both sides exactly once", wsCloses === 1 && tcpCloses === 1);
    check("TCP close rejection does not escape tunnel cleanup", unhandled.length === 0);

    const peer = new EventTarget();
    Object.assign(peer, { send() {}, close() {} });
    let source2!: ReadableStreamDefaultController<Uint8Array>;
    let finishClose!: () => void;
    const closing = new Promise<void>(resolve => { finishClose = resolve; });
    const socket2 = {
      readable: new ReadableStream<Uint8Array>({ start(controller) { source2 = controller; } }),
      writable: new WritableStream<Uint8Array>(),
      close() { source2.close(); return closing; },
    };
    let completed = false;
    const completion = Promise.resolve(pipe(peer as unknown as WebSocket, socket2, new Uint8Array()))
      .then(() => { completed = true; });
    await new Promise(resolve => setTimeout(resolve, 0));
    check("session completion stays pending while the tunnel is open", !completed);
    peer.dispatchEvent(new Event("close"));
    await new Promise(resolve => setTimeout(resolve, 0));
    check("session completion waits for asynchronous TCP cleanup", !completed);
    finishClose();
    await completion;
    check("session completion settles after TCP cleanup", completed);
  } finally {
    process.removeListener("unhandledRejection", onUnhandled);
  }
}

async function main(): Promise<void> {
  console.log("inbrowser-relay test suite - no network required\n");
  try {
    await testHandshakes();
    testDialPolicy();
    await testCrypto();
    await testConformance();
    await testPipeShutdown();
    testLayering();
  } catch (err) {
    failures++;
    console.error("\nUnexpected error:", err instanceof Error ? err.stack : err);
  }

  console.log(`\n${checks - failures}/${checks} checks passed`);
  if (failures > 0) {
    console.error(`${failures} failed`);
    process.exit(1);
  }
  process.exit(0);
}

void main();
