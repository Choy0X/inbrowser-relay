# inbrowser-relay

**A zero-knowledge egress pipe, deployed as a Cloudflare Worker.**

It accepts a WebSocket, opens a TCP socket with `connect()` from `cloudflare:sockets`, performs
an HTTP CONNECT, SOCKS5 or SOCKS4/4a handshake against a user-supplied proxy, and moves bytes.
It is deliberately dumb: the dial arrives AES-256-GCM sealed and everything after the handshake
is somebody else's TLS session, so there is nothing here that can read what passes through.

This is the egress half of proxy support for [**InBrowser**](https://inbrowser.tech), a
browser-based AI workspace. The other half, the relay service that terminates TLS to the
provider, lives in the [app repository](https://github.com/Choy0X/Inbrowser) under `server/`.
The two are separate repositories because they are separately deployed and have separate
lifecycles: nothing here is bundled into the app, and updating one does not require redeploying
the other.

```
browser -> relay service (app repo, server/) -> THIS WORKER -> user's proxy -> provider
```

## Contents

- [Why it exists](#why-it-exists)
- [What it can see](#what-it-can-see)
- [Architecture](#architecture)
- [Limits it enforces](#limits-it-enforces)
- [Deploy](#deploy)
- [Tests](#tests)
- [Staying in sync with the app repository](#staying-in-sync-with-the-app-repository)
- [License](#license)

## Why it exists

Whatever dials a proxy reveals its IP address to whoever operates that proxy. InBrowser users can
point the app at any proxy, including one they run themselves, so if the relay service dialled
proxies directly, anyone could learn its address by configuring a proxy of their own and reading
their own logs.

This Worker sits in front, so the address a proxy operator sees is Cloudflare's anycast edge
instead of a specific machine.

## What it can see

Nothing readable.

- **The dial** (proxy host, port, username, password) arrives AES-256-GCM sealed under
  `RELAY_SECRET`, with the key derived through HKDF.
- **Everything after the handshake** is the relay service's TLS session with the provider, for
  which this Worker has no key material at any point. There is no TLS-in-TLS anywhere: the outer
  TLS is Cloudflare's and the inner TLS is Node's.

`RELAY_SECRET` is also the access control. The Worker's URL is public, but a dial cannot be
sealed without the secret, so this is not an open relay.

> ### Never add logging
>
> Not the target host, not a dial field, not "just while debugging". `logpush` is off in
> `wrangler.toml` for the same reason. InBrowser tells users, in its privacy policy, that this
> component keeps no record of what passes through it, and a single `console.log` of a dial field
> makes that claim false. **The test suite greps for this and fails the build.**
>
> To debug, reproduce locally with `npm test`, which drives these same modules against loopback
> servers.

## Architecture

| File | Role |
|---|---|
| `src/index.ts` | The Worker entry point. **The only file that imports `cloudflare:sockets`.** |
| `src/dial.ts` | Dial policy: port rules, address rules, target validation |
| `src/crypto.ts` | HKDF key derivation and AES-256-GCM seal/open |
| `src/protocol.ts` | Wire frame encode/decode, protocol version, close codes |
| `src/conformance.ts` | The frozen cross-repository wire-format vector |
| `src/pipe.ts` | Byte pumping, with the per-tunnel limits applied |
| `src/bufreader.ts` | Buffered reads over a byte stream |
| `src/handshake/` | `connect.ts`, `socks5.ts`, `socks4.ts` and their shared types |

### The layering rule

`cloudflare:sockets` is imported in **exactly one file**, and every handshake takes a
`{ reader, writer }` pair rather than a `Socket`.

That is what lets `npm test` run the real production handshake code under plain Node, with
`stream.Duplex.toWeb()` standing in for the Workers socket API. There is no mock implementation
of the handshakes to drift from the real one. The test suite greps for violations of this rule
and fails the build.

## Limits it enforces

| Limit | Value | Why |
|---|---|---|
| Target ports | 80 and 443 only | The single most effective control: it stops this being a general-purpose TCP proxy |
| Proxy ports | 22, 23, 25, 465, 587, 6667 denied | The ports whose abuse gets a Cloudflare account terminated |
| Addresses | private, loopback and link-local refused | See the caveat below |
| Dial frame | 4 KiB | |
| Dial age | 60 s | Bounds replay without needing shared state |
| Per tunnel | 64 MiB, 10 min, 60 s idle | Bounds the blast radius of a stuck connection |
| Dial rate | 60 per minute | Cloudflare rate-limiter binding, `DIAL_LIMITER` in `wrangler.toml` |

> **SSRF caveat, stated plainly.** The Worker runtime has no DNS resolver, so a *public hostname
> that resolves to a private address* passes every check `dial.ts` can make. We rely on
> Cloudflare's own `connect()` restrictions for that case. Confirm that reliance holds before
> running a public relay; if it does not, this needs a target-host allowlist.

## Deploy

```bash
npm install
openssl rand -hex 32 | npx wrangler secret put RELAY_SECRET
npx wrangler deploy
```

Then:

1. Put the **same** `RELAY_SECRET` in the relay service's environment. It has to match, not
   merely exist.
2. Point the relay service's `WORKER_URL` at `wss://<your-worker>.workers.dev/v1`.
3. Set `ALLOWED_ORIGINS` in `wrangler.toml` to your app's origin. Comma-separated, and each
   entry may be a full origin (`https://example.com`, scheme pinned), a bare host
   (`example.com`, any scheme), or a wildcard (`*.example.com`, which covers that host **and**
   anything beneath it). Leaving it empty allows any origin, which is the sensible default for a
   relay only you can reach.

   Note that an Origin check is a floor, not a boundary: browsers cannot forge it, but any
   non-browser client can, and a request carrying no Origin header at all is not subject to it.
   `RELAY_SECRET` is the control that matters.

### Manual check after deploying

`npm test` covers the protocol logic but deliberately skips the TLS leg, which needs certificates
to test and is Node's own stack doing its job. So after deploying, once:

1. Deploy this Worker and the relay service with a matching `RELAY_SECRET`.
2. Point Settings > Proxies > Relay at the relay service.
3. Add one real proxy and press **Test**. It should report the proxy's egress IP.
4. Run a streamed chat and confirm tokens arrive progressively, not in one burst.
5. Run a web search and an image generation.
6. Confirm the provider sees the proxy's IP, not yours.

## Tests

```bash
npm install
npm test           # 114 checks, no network required
npm run typecheck
```

`npm test` drives the production handshake modules against real SOCKS5, SOCKS4/4a and HTTP
CONNECT servers on loopback. It asserts the request bytes exactly, checks every failure mapping
and the coalesced-leftover case, exercises the dial policy against every legal spelling of
`127.0.0.1`, checks the Origin policy including the suffix trap that would let
`evilinbrowser.tech` through a naive `*.inbrowser.tech` match, verifies sealing, tampering and
replay rejection, and greps the source for logging and layering violations.

## Staying in sync with the app repository

`src/protocol.ts` and `src/crypto.ts` have counterparts in the app repo under `server/src/`. They
used to be byte-identical twins checked by a file comparison; across a repository boundary that
is impossible, so the wire format is pinned by **`src/conformance.ts`** instead: a frozen sealed
dial frame that both repositories assert they can open with their own key derivation.

That catches every drift that matters. A changed HKDF info string, salt, cipher, key length, tag
length, frame layout or JSON field name all make the vector fail to open. It cannot catch a
change made deliberately and identically on both sides, which is correct: that is a protocol
revision, and it should bump `PROTOCOL_VERSION` and regenerate the vector.

**If the conformance check fails, the two repositories disagree about the wire format. Do not
regenerate the vector to make it pass. Find which side changed.**

A version mismatch is also caught at runtime: `decodeDialFrame` rejects a frame whose version
byte it does not recognise, so a half-upgraded deployment fails loudly rather than behaving
strangely.

## License

See [LICENSE](./LICENSE): free to clone, use and modify with attribution to **Choy0X**;
publishing or hosting a public instance is reserved to the author.

---

<div align="center">
  <sub>
    The app this serves: <a href="https://inbrowser.tech">inbrowser.tech</a> &middot;
    <a href="https://github.com/Choy0X/Inbrowser">Choy0X/Inbrowser</a>
  </sub>
</div>
