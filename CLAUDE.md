# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm install
npm test              # 114 checks, no network required
npm run typecheck
npx wrangler dev       # local Worker dev server
npx wrangler deploy    # deploy (requires RELAY_SECRET already set, see below)
```

There is no single-test runner - `npm test` bundles `test/run.ts` with esbuild and runs it as one script (`section()`/`check()` calls print a running tally); narrow a run by temporarily commenting out the other `test*()` calls in `main()` at the bottom of `test/run.ts`.

Deploying for the first time:
```bash
openssl rand -hex 32 | npx wrangler secret put RELAY_SECRET
npx wrangler deploy
```
The identical `RELAY_SECRET` value must also be set in the app repo's environment (`WORKER_URL` there must point at `wss://<this-worker>/v1`) - a mismatch fails every dial with `DIAL_DECRYPT_FAILED` rather than degrading gracefully.

## Architecture

This is the egress half of InBrowser's proxy-relay feature: a Cloudflare Worker that is a **dumb encrypted byte pipe**. It accepts a WebSocket, seals-decrypts and validates a dial request, opens a TCP socket to the user's proxy via `connect()` from `cloudflare:sockets`, performs the proxy handshake, then pumps raw bytes both ways. It never sees plaintext - the dial (proxy host/port/credentials) is AES-256-GCM sealed under `RELAY_SECRET`, and everything after the proxy handshake is the app repo's own TLS session to the real provider, for which this Worker has no key material.

**The other half lives in a separate repository** - the app repo's `server/` (Fastify), which terminates TLS to the provider and is the only thing that ever sees plaintext or credentials. The split is deliberate: separate deployment, separate lifecycle, and it bounds what a compromise of either component can see. `inbrowser/CLAUDE.md`'s "The proxy relay" section documents the app-side half and the shared invariants; this file only covers what's specific to this repo.

**Request flow, `src/index.ts`** (the *only* file permitted to import `cloudflare:sockets` - `npm test` greps for violations and fails the build): `fetch()` handles `/health` (liveness) and upgrades `/v1` to a WebSocket, then hands off to `runSession()`. That session is registered with `ctx.waitUntil()`, not a bare `void` call - without that, the platform has no signal the background work is expected once the `101` response has been returned, and will kill the isolate as a "hung" invocation, observed in production. `runSession()` reads exactly one binary frame (the sealed dial), decrypts and validates it (`crypto.ts` + `dial.ts`), dials the proxy, runs the matching handshake (`handshake/connect.ts` for HTTP/HTTPS CONNECT, `handshake/socks4.ts`, `handshake/socks5.ts`), sends a READY control frame, then calls `pipe()` (`pipe.ts`) to move bytes until either side closes or a limit (`DEFAULT_LIMITS`: 64 MiB / 10 min / 60 s idle) is hit. Every failure before READY sends an ERROR control frame carrying a `RelayClose` code (`protocol.ts`) and closes with that code, so a client watching only `onclose` still gets a machine-readable reason.

**Two timeouts bound the pre-READY worst case to 25s**, both in `index.ts`: `firstBinaryFrame()`'s 10s wait for the dial frame, plus `HANDSHAKE_TIMEOUT_MS` (15s) wrapping the handshake call. The app repo's own `openTunnel()` (`server/src/workerTunnel.ts`, `DEFAULT_OPEN_TIMEOUT_MS`) deliberately budgets more than this (currently 35s) so it outlasts this Worker's own worst case plus network time to reach it - the two constants are cross-referenced by comment in both repos and must be changed together.

**Layering rule for testability**: every handshake function takes a `{ reader, writer }` pair, never a raw `Socket` - that's what lets `test/run.ts` drive the *production* handshake code under plain Node against real loopback SOCKS4/SOCKS5/CONNECT servers (`test/proxyServers.ts`), with `stream.Duplex.toWeb()` standing in for the Workers socket API. TLS itself (the leg from this Worker to an `https://` proxy) is *not* exercised by `npm test` - it needs real certificates and is Node's/workerd's own stack doing its job; the README's "Manual check after deploying" section is the only coverage for that leg.

**Staying in sync with the app repository**: `protocol.ts` and `crypto.ts` have byte-identical-in-intent counterparts under the app repo's `server/src/`. Across a repo boundary that can't be enforced by a file diff, so `conformance.ts` pins the wire format instead - a frozen sealed dial frame that both repos assert they can open with their own key derivation. If the conformance check fails, the two repos disagree about the wire format; **do not regenerate the vector to make it pass** - find which side changed.

**What counts as a protocol revision.** Not every matching change on both sides is one, and treating them all as one is expensive: `decodeDialFrame` rejects an unrecognised version byte and the Worker maps every `openDial` throw to `DIAL_DECRYPT_FAILED`, so bumping `PROTOCOL_VERSION` makes a half-upgraded deployment a total outage of the proxy feature, reported to users as an authentication failure that points at the secret rather than the version. Two cases:

- **Adding an optional field to the sealed payload, where both sides tolerate its absence.** Regenerate the vector in both repos in the same change; do **not** bump. `openDial` already ignores unknown fields, so an older Worker skips it and a newer one falls back - which makes the rollout ordinary rather than a flag day. `bucket` was added this way.
- **Anything that changes the bytes or their meaning** - frame layout, cipher, HKDF info or salt, key or tag length, a renamed or removed field. Bump `PROTOCOL_VERSION`, and deploy the Worker first with it accepting both the old and new version before narrowing it.

Regenerate the vector with `scripts/gen-conformance-vector.ts` in the app repo and paste the output into both `conformance.ts` files verbatim. Keep the vector's `bucket` a literal: if it were derived from `VECTOR_SECRET`, the vector would also be testing the bucket derivation and a failure could no longer say which of the two moved.

**Never add logging.** Not the target host, not a dial field, not "just while debugging" - `logpush` is off in `wrangler.toml` for the same reason, and `npm test` asserts both (`src/index.ts logs no dial field`, `logpush is disabled`). The app's privacy policy tells users this component keeps no record of what passes through it; a stray `console.log` of a dial field makes that claim false. Reproduce issues locally with `npm test` instead.

**Enforced limits and the one open caveat**: target ports are restricted to 80/443, common proxy-abuse ports are denied, and private/loopback/link-local addresses are refused in `dial.ts` - but the Workers runtime has no DNS resolver, so a public hostname that resolves to a private address passes every check this repo can make; the README states plainly that this relies on Cloudflare's own `connect()` restrictions and flags it as needing a target-host allowlist if that reliance doesn't hold.

## Push the changes always

Once a change here builds cleanly (`npm run typecheck`) and `npm test` passes, commit and push it without waiting to be asked again for that same change.
