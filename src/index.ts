/**
 * InBrowser proxy relay - the Cloudflare Worker half.
 *
 * WHAT THIS IS FOR. A browser cannot speak HTTP CONNECT or SOCKS, so a real
 * proxy needs something server-side to dial it. Whatever dials the proxy reveals
 * its IP address to the proxy's operator - and a user can point the app at a
 * proxy they control. If the VPS relay dialled directly, anyone could learn its
 * address by configuring a proxy of their own and reading the logs. This Worker
 * exists so the address the proxy sees is Cloudflare's anycast edge instead.
 *
 * WHAT IT CAN SEE: effectively nothing. The dial is AES-256-GCM sealed under
 * RELAY_SECRET, and everything after the handshake is the VPS's TLS session
 * with the provider. It handles a stream of bytes it cannot decrypt.
 *
 * NEVER ADD LOGGING HERE. Not the target host, not the dial, not a header, not
 * "just while debugging". `logpush` is off in wrangler.toml for the same reason.
 * The app tells users in PrivacyPolicyContent.tsx that this component keeps no
 * record of what passes through it, and a console.log of a dial field makes that
 * claim false. If you need to debug, reproduce it locally with
 * `npm run verify:relay`, which drives these same modules against loopback
 * servers.
 *
 * LAYERING RULE: this is the only file permitted to import `cloudflare:sockets`.
 * Every handshake takes a `{ reader, writer }` pair so the protocol logic runs
 * unmodified under Node in the verify script. `verify:relay` greps for
 * violations and fails the build.
 */
import { connect } from "cloudflare:sockets";
import { BufferedReader } from "./bufreader";
import { deriveDialKey, openDial } from "./crypto";
import { isOriginAllowed, validateDial } from "./dial";
import { connectHandshake } from "./handshake/connect";
import { socks4Handshake } from "./handshake/socks4";
import { socks5Handshake } from "./handshake/socks5";
import { HandshakeError, type Handshake } from "./handshake/types";
import { DEFAULT_LIMITS, pipe } from "./pipe";
import {
  MAX_DIAL_FRAME_BYTES,
  RelayClose,
  encodeErrorFrame,
  encodeReadyFrame,
  type DialRequest,
} from "./protocol";

export interface Env {
  /** Shared with the VPS relay. Without it a dial cannot be sealed, so the Worker is not an open relay. */
  RELAY_SECRET: string;
  /** Comma-separated origins allowed to open a tunnel. Empty allows any, for self-hosters. */
  ALLOWED_ORIGINS?: string;
  /** Optional Cloudflare rate-limit binding, keyed on the VPS address. */
  DIAL_LIMITER?: { limit(options: { key: string }): Promise<{ success: boolean }> };
}

/** `http` and `https` share the CONNECT bytes; only the socket underneath differs. */
const HANDSHAKES: Record<DialRequest["protocol"], Handshake> = {
  http: connectHandshake,
  https: connectHandshake,
  socks5: socks5Handshake,
  socks4: socks4Handshake,
};

/**
 * How long the proxy has to finish its handshake before we give up on it.
 * Together with firstBinaryFrame()'s 10s dial-frame wait below, this bounds
 * the Worker's worst case at 25s before it guarantees an ERROR frame or
 * close. The other repo's openTunnel() (inbrowser/server/src/workerTunnel.ts,
 * DEFAULT_OPEN_TIMEOUT_MS) budgets 35s specifically to outlast this plus
 * network time - if you raise either constant here, raise that one too.
 */
const HANDSHAKE_TIMEOUT_MS = 15_000;

/** How long DIAL_LIMITER gets to answer before this request fails open. See the call site. */
const RATE_LIMIT_TIMEOUT_MS = 1_000;

const VERSION = "1.0.0";

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    if (url.pathname === "/health") {
      return Response.json(
        {
          ok: true,
          version: VERSION,
          // Diagnostic only, added to debug a RELAY_SECRET mismatch between this
          // Worker and the VPS app. relaySecretPreview exposes real secret bytes
          // on a public, unauthenticated endpoint - remove it once the deployment
          // is confirmed configured correctly rather than leaving it standing.
          relaySecretConfigured: Boolean(env.RELAY_SECRET),
          //relaySecretPreview: env.RELAY_SECRET ? env.RELAY_SECRET.slice(0, 4) : null,
        },
        { headers: corsHeaders() }
      );
    }

    if (url.pathname !== "/v1") {
      return new Response("Not found", { status: 404, headers: corsHeaders() });
    }

    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("Expected a WebSocket upgrade", { status: 426, headers: corsHeaders() });
    }

    // An Origin check is a floor, not a boundary: a browser cannot forge it, but
    // any non-browser client can. It keeps other websites and casual scripted
    // abuse out. RELAY_SECRET is the control that actually matters.
    const allowed = (env.ALLOWED_ORIGINS ?? "").split(",").map((o) => o.trim()).filter(Boolean);
    const origin = request.headers.get("Origin");
    if (allowed.length > 0 && origin && !isOriginAllowed(origin, allowed)) {
      return new Response("Origin not allowed", { status: 403, headers: corsHeaders() });
    }

    if (env.DIAL_LIMITER) {
      // DIAL_LIMITER is declared via wrangler.toml's [[unsafe.bindings]] -
      // wrangler itself warns at deploy time that "unsafe" fields are
      // experimental and may change or break at any time. This is the only
      // await before the WebSocket exists and the response is returned, so a
      // slow or hung binding here stalls the whole invocation with nothing
      // to react to - exactly the "Worker's code had hung" failure, observed
      // in production. Bounded and fail-open: RELAY_SECRET is the control
      // that actually matters (see the Origin check above for the same
      // reasoning), this is defense in depth, not the thing standing between
      // the relay and abuse.
      const key = request.headers.get("cf-connecting-ip") ?? "unknown";
      try {
        const { success } = await withTimeout(env.DIAL_LIMITER.limit({ key }), RATE_LIMIT_TIMEOUT_MS);
        if (!success) {
          return new Response("Too many requests", { status: 429, headers: corsHeaders() });
        }
      } catch {
        /* fail open - see comment above */
      }
    }

    if (!env.RELAY_SECRET) {
      return new Response("Relay is not configured", { status: 503, headers: corsHeaders() });
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();

    // Detached from the response - it must return immediately so the upgrade
    // completes - but registered with the runtime via waitUntil. This task
    // includes the handshake, byte pumps and asynchronous TCP cleanup so work
    // remains owned by the invocation when its WebSocket closes.
    ctx.waitUntil(
      runSession(server, env).catch(() => {
        try {
          server.close(RelayClose.UPSTREAM_CLOSED, "");
        } catch {
          /* already gone */
        }
      })
    );

    return new Response(null, { status: 101, webSocket: client });
  },
};

function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "content-type",
    "Cache-Control": "no-store",
  };
}

/**
 * Waits for frame 0, opens it, dials, hands off to the pump. Every failure
 * before READY sends an ERROR frame (whose message can exceed the 123-byte
 * close-reason limit and so reaches the user's Settings test verbatim) and then
 * closes with the matching code, so a client watching only `onclose` still gets
 * something machine-readable.
 */
async function runSession(ws: WebSocket, env: Env): Promise<void> {
  const fail = (code: number, message: string) => {
    try {
      ws.send(encodeErrorFrame(code, message));
      ws.close(code, message.slice(0, 120));
    } catch {
      /* peer already gone */
    }
  };

  let frame: Uint8Array;
  try {
    frame = await raceClientGone(ws, firstBinaryFrame(ws));
  } catch {
    fail(RelayClose.DIAL_REJECTED, "The relay did not receive a dial.");
    return;
  }

  let dial: DialRequest;
  try {
    const key = await deriveDialKey(env.RELAY_SECRET);
    dial = await openDial(key, frame);
  } catch {
    // Deliberately one message for every cause - a bad tag, a malformed frame,
    // a stale timestamp. Distinguishing them would make this an oracle for
    // anyone probing the seal.
    fail(RelayClose.DIAL_DECRYPT_FAILED, "The relay could not authenticate this request.");
    return;
  }

  const rejection = validateDial(dial);
  if (rejection) {
    fail(rejection.code, rejection.message);
    return;
  }

  // `secureTransport: "on"` is what makes an https:// proxy work: the hop to the
  // proxy is TLS here, and the VPS layers the provider's TLS inside the tunnel.
  // Neither side is ever asked for TLS-in-TLS, which workerd cannot do.
  let socket: ReturnType<typeof connect>;
  try {
    socket = connect(
      { hostname: dial.host, port: dial.port },
      {
        secureTransport: dial.protocol === "https" ? "on" : "off",
        // false lets the writable side close on EOF, which is what we want:
        // pipe.ts tears down both directions together anyway.
        allowHalfOpen: false,
      }
    );
  } catch {
    fail(RelayClose.PROXY_UNREACHABLE, "Could not reach the proxy.");
    return;
  }

  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();
  let leftover: Uint8Array;
  try {
    const handshake = HANDSHAKES[dial.protocol];
    const result = await raceClientGone(
      ws,
      withTimeout(handshake({ reader: new BufferedReader(reader), writer }, dial), HANDSHAKE_TIMEOUT_MS)
    );
    leftover = result.leftover;
  } catch (err) {
    const message =
      err instanceof HandshakeError
        ? err.message
        : err instanceof TimeoutError
          ? "The proxy did not complete its handshake in time."
          : "Could not reach the proxy.";
    const code = err instanceof HandshakeError ? RelayClose.HANDSHAKE_FAILED : RelayClose.PROXY_UNREACHABLE;
    fail(code, message);
    try {
      reader.releaseLock();
      writer.releaseLock();
      void socket.close().catch(() => {});
    } catch {
      /* already torn down */
    }
    return;
  }

  reader.releaseLock();
  writer.releaseLock();
  ws.send(encodeReadyFrame());
  // Keep the waitUntil task alive through the byte pumps and their async TCP
  // cleanup, including when the VPS closes after a TLS verification failure.
  await pipe(ws, socket, leftover, DEFAULT_LIMITS);
}

/**
 * Rejects as soon as the client side of the WebSocket closes or errors,
 * racing whichever settles first against `promise`. Cloudflare's runtime
 * expects the server side to react promptly when the peer goes away -
 * leaving that unhandled is exactly the "Worker's code had hung" failure
 * (https://developers.cloudflare.com/workers/observability/errors/), which
 * showed up in production well inside these steps' own timeouts. pipe()
 * (post-READY) already has its own close/error handling; this covers every
 * step before that - waiting for the dial frame and running the handshake.
 */
function raceClientGone<T>(ws: WebSocket, promise: Promise<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      ws.removeEventListener("close", onClose);
      ws.removeEventListener("error", onError);
    };
    const onClose = () => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new Error("The client closed the connection."));
    };
    const onError = () => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new Error("The client connection errored."));
    };
    ws.addEventListener("close", onClose);
    ws.addEventListener("error", onError);
    promise.then(
      (value) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(value);
      },
      (err) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(err);
      }
    );
  });
}

function firstBinaryFrame(ws: WebSocket): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    // See the comment on HANDSHAKE_TIMEOUT_MS above: this 10s wait is the
    // other half of the Worker's 25s worst-case budget.
    const timer = setTimeout(() => reject(new Error("No dial frame")), 10_000);
    const onMessage = (event: MessageEvent) => {
      clearTimeout(timer);
      ws.removeEventListener("message", onMessage as EventListener);
      if (typeof event.data === "string") {
        reject(new Error("Dial frame must be binary"));
        return;
      }
      const bytes = new Uint8Array(event.data as ArrayBuffer);
      if (bytes.length > MAX_DIAL_FRAME_BYTES) {
        reject(new Error("Dial frame too large"));
        return;
      }
      resolve(bytes);
    };
    ws.addEventListener("message", onMessage as EventListener);
  });
}

class TimeoutError extends Error {}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new TimeoutError()), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      }
    );
  });
}
