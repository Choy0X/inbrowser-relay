/**
 * Minimal SOCKS5, SOCKS4/4a and HTTP CONNECT servers on loopback, for
 * `npm test`.
 *
 * These exist so the relay's real handshake modules can be driven against
 * something that actually speaks the protocols, with no third-party proxy and no
 * network. Each server records the exact handshake bytes it received, which is
 * what lets the verify script assert byte-for-byte rather than merely "it
 * connected" - ATYP, length-prefix and endianness mistakes all produce a working
 * connection against a lenient server and a broken one against a real proxy.
 *
 * Each can also be told to fail in a specific way, so the mapping from a
 * protocol-level refusal to a user-facing message is tested rather than assumed.
 */
import net from "node:net";

export interface TestProxy {
  port: number;
  /** Handshake bytes the client sent, concatenated. */
  received(): Buffer;
  close(): Promise<void>;
}

export type Socks5Mode = "noauth" | "userpass" | "reject-auth" | "no-methods" | "rep5" | "ipv6-bnd";
export type Socks4Mode = "granted" | "rejected" | "identd";
export type ConnectMode = "ok" | "ok-201" | "auth-required" | "bad-gateway" | "coalesce";

function listen(server: net.Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve((server.address() as net.AddressInfo).port));
  });
}

function closer(server: net.Server, sockets: Set<net.Socket>): () => Promise<void> {
  return () =>
    new Promise((resolve) => {
      for (const s of sockets) s.destroy();
      server.close(() => resolve());
    });
}

/** Pipes a handshake-completed client socket to the real target it asked for. */
function bridge(client: net.Socket, host: string, port: number, sockets: Set<net.Socket>): void {
  const upstream = net.connect(port, host);
  sockets.add(upstream);
  upstream.on("error", () => client.destroy());
  client.on("error", () => upstream.destroy());
  client.pipe(upstream);
  upstream.pipe(client);
}

export async function startSocks5(mode: Socks5Mode = "noauth"): Promise<TestProxy> {
  const chunks: Buffer[] = [];
  const sockets = new Set<net.Socket>();

  const server = net.createServer((socket) => {
    sockets.add(socket);
    let stage: "greeting" | "auth" | "request" | "done" = "greeting";
    let buf = Buffer.alloc(0);

    socket.on("data", (data) => {
      if (stage !== "done") chunks.push(Buffer.from(data));
      buf = Buffer.concat([buf, data]);

      if (stage === "greeting") {
        if (buf.length < 2) return;
        const n = buf[1];
        if (buf.length < 2 + n) return;
        const offered = new Set(buf.subarray(2, 2 + n));
        buf = buf.subarray(2 + n);

        if (mode === "no-methods") {
          socket.end(Buffer.from([0x05, 0xff]));
          return;
        }
        const wantsAuth = mode === "userpass" || mode === "reject-auth";
        if (wantsAuth && !offered.has(0x02)) {
          socket.end(Buffer.from([0x05, 0xff]));
          return;
        }
        socket.write(Buffer.from([0x05, wantsAuth ? 0x02 : 0x00]));
        stage = wantsAuth ? "auth" : "request";
        if (buf.length === 0) return;
      }

      if (stage === "auth") {
        if (buf.length < 2) return;
        const ulen = buf[1];
        if (buf.length < 2 + ulen + 1) return;
        const plen = buf[2 + ulen];
        if (buf.length < 3 + ulen + plen) return;
        buf = buf.subarray(3 + ulen + plen);
        if (mode === "reject-auth") {
          socket.end(Buffer.from([0x01, 0x01]));
          return;
        }
        socket.write(Buffer.from([0x01, 0x00]));
        stage = "request";
        if (buf.length === 0) return;
      }

      if (stage === "request") {
        if (buf.length < 4) return;
        const atyp = buf[3];
        let host: string;
        let offset: number;
        if (atyp === 0x01) {
          if (buf.length < 10) return;
          host = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`;
          offset = 8;
        } else if (atyp === 0x03) {
          const len = buf[4];
          if (buf.length < 5 + len + 2) return;
          host = buf.subarray(5, 5 + len).toString("utf8");
          offset = 5 + len;
        } else if (atyp === 0x04) {
          if (buf.length < 22) return;
          host = "::1";
          offset = 20;
        } else {
          socket.end(Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          return;
        }
        const port = buf.readUInt16BE(offset);
        buf = buf.subarray(offset + 2);
        stage = "done";

        if (mode === "rep5") {
          socket.end(Buffer.from([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          return;
        }

        // A variable-length bound address is the interesting case: the client
        // must parse it to know where the tunnel begins.
        const reply =
          mode === "ipv6-bnd"
            ? Buffer.concat([Buffer.from([0x05, 0x00, 0x00, 0x04]), Buffer.alloc(16), Buffer.from([0x1f, 0x90])])
            : Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90]);
        socket.write(reply);

        // Localhost targets are resolved here rather than by the dial policy;
        // policy is tested separately against dial.ts.
        bridge(socket, host === "::1" ? "127.0.0.1" : host, port, sockets);
        if (buf.length > 0) socket.emit("data", buf);
      }
    });
  });

  const port = await listen(server);
  return { port, received: () => Buffer.concat(chunks), close: closer(server, sockets) };
}

export async function startSocks4(mode: Socks4Mode = "granted"): Promise<TestProxy> {
  const chunks: Buffer[] = [];
  const sockets = new Set<net.Socket>();

  const server = net.createServer((socket) => {
    sockets.add(socket);
    let buf = Buffer.alloc(0);
    let done = false;

    socket.on("data", (data) => {
      if (!done) chunks.push(Buffer.from(data));
      buf = Buffer.concat([buf, data]);
      if (done || buf.length < 9) return;

      const port = buf.readUInt16BE(2);
      const a = buf[4], b = buf[5], c = buf[6], d = buf[7];
      const is4a = a === 0 && b === 0 && c === 0 && d !== 0;

      const idEnd = buf.indexOf(0x00, 8);
      if (idEnd === -1) return;

      let host: string;
      let end: number;
      if (is4a) {
        const hostEnd = buf.indexOf(0x00, idEnd + 1);
        if (hostEnd === -1) return;
        host = buf.subarray(idEnd + 1, hostEnd).toString("utf8");
        end = hostEnd + 1;
      } else {
        host = `${a}.${b}.${c}.${d}`;
        end = idEnd + 1;
      }
      buf = buf.subarray(end);
      done = true;

      const status = mode === "granted" ? 0x5a : mode === "rejected" ? 0x5b : 0x5c;
      socket.write(Buffer.from([0x00, status, (port >> 8) & 0xff, port & 0xff, a, b, c, d]));
      if (status !== 0x5a) {
        socket.end();
        return;
      }
      bridge(socket, host, port, sockets);
      if (buf.length > 0) socket.emit("data", buf);
    });
  });

  const port = await listen(server);
  return { port, received: () => Buffer.concat(chunks), close: closer(server, sockets) };
}

export async function startConnectProxy(mode: ConnectMode = "ok"): Promise<TestProxy> {
  const chunks: Buffer[] = [];
  const sockets = new Set<net.Socket>();

  const server = net.createServer((socket) => {
    sockets.add(socket);
    let buf = Buffer.alloc(0);
    let done = false;

    socket.on("data", (data) => {
      if (!done) chunks.push(Buffer.from(data));
      buf = Buffer.concat([buf, data]);
      if (done) return;
      const headEnd = buf.indexOf("\r\n\r\n");
      if (headEnd === -1) return;

      const head = buf.subarray(0, headEnd).toString("utf8");
      buf = buf.subarray(headEnd + 4);
      done = true;

      if (mode === "auth-required") {
        socket.end("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
        return;
      }
      if (mode === "bad-gateway") {
        socket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
        return;
      }

      const authority = /^CONNECT\s+(\S+)/.exec(head)?.[1] ?? "";
      const lastColon = authority.lastIndexOf(":");
      const host = authority.slice(0, lastColon);
      const port = Number(authority.slice(lastColon + 1));

      const status = mode === "ok-201" ? "201 Connection established" : "200 Connection established";

      if (mode === "coalesce") {
        // Deliberately glues the first tunnel byte onto the handshake reply:
        // the exact case a handshake that drops its leftover gets wrong.
        socket.write(`HTTP/1.1 ${status}\r\n\r\nLEFTOVER`);
        return;
      }

      socket.write(`HTTP/1.1 ${status}\r\n\r\n`);
      bridge(socket, host, port, sockets);
      if (buf.length > 0) socket.emit("data", buf);
    });
  });

  const port = await listen(server);
  return { port, received: () => Buffer.concat(chunks), close: closer(server, sockets) };
}
