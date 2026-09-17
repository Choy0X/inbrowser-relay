/**
 * Sealing and opening the dial frame.
 *
 * THIS FILE IS A TWIN of `server/src/crypto.ts`; see the note at the top of
 * protocol.ts. It uses only WebCrypto, which Node 18+ and workerd both expose
 * as `globalThis.crypto.subtle`, so one implementation serves both sides and
 * there is no chance of the two disagreeing about key derivation.
 *
 * Why the dial is encrypted rather than merely signed: it carries the user's
 * proxy credentials. A signature would authenticate the VPS to the Worker but
 * leave those credentials readable by anything that records the WebSocket
 * handshake - including Cloudflare itself. AES-256-GCM gives authentication
 * (the tag is a MAC over the whole payload) and confidentiality in one pass, so
 * the Worker both proves the dial came from a holder of RELAY_SECRET and is
 * itself unable to read the credentials it is dialling with... except insofar
 * as it must decrypt them to use them. The property that actually holds is the
 * narrower one: nobody on the path between VPS and Worker can read them, and
 * nobody without RELAY_SECRET can forge a dial, which is what keeps a publicly
 * reachable Worker from being an open relay.
 */
import {
  DIAL_MAX_AGE_MS,
  IV_BYTES,
  decodeDialFrame,
  encodeDialFrame,
  type DialRequest,
} from "./protocol";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Domain separation, so the same secret could safely derive other keys later. */
const HKDF_INFO = encoder.encode("inbrowser-relay-dial-v1");

/**
 * HKDF-SHA256 over RELAY_SECRET. No salt: the secret is already high-entropy
 * (the deploy docs specify `openssl rand -hex 32`) and a fixed empty salt keeps
 * both sides derivable from the secret alone, with no extra value to distribute.
 */
export async function deriveDialKey(secret: string): Promise<CryptoKey> {
  if (!secret || secret.length < 32) {
    throw new Error("RELAY_SECRET must be at least 32 characters. Generate one with: openssl rand -hex 32");
  }
  const material = await crypto.subtle.importKey("raw", encoder.encode(secret), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: HKDF_INFO },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/** Seals a dial into a complete frame, ready to be sent as WebSocket frame 0. */
export async function sealDial(key: CryptoKey, dial: DialRequest): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const plaintext = encoder.encode(JSON.stringify(dial));
  const sealed = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return encodeDialFrame(iv, new Uint8Array(sealed));
}

/**
 * Opens and validates a dial frame. Throws on a bad tag, a malformed frame, a
 * non-object payload, or a stale timestamp - the caller maps any throw to
 * RelayClose.DIAL_DECRYPT_FAILED without distinguishing which, deliberately, so
 * the Worker is not an oracle for why a forgery attempt failed.
 */
export async function openDial(key: CryptoKey, frame: Uint8Array, now = Date.now()): Promise<DialRequest> {
  const { iv, ciphertext } = decodeDialFrame(frame);
  const opened = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  const parsed: unknown = JSON.parse(decoder.decode(new Uint8Array(opened)));
  if (!parsed || typeof parsed !== "object") throw new Error("Dial payload is not an object");
  const dial = parsed as DialRequest;
  if (typeof dial.ts !== "number" || !Number.isFinite(dial.ts)) throw new Error("Dial has no timestamp");
  // Absolute value: a clock skewed into the future is as suspect as a replay.
  if (Math.abs(now - dial.ts) > DIAL_MAX_AGE_MS) throw new Error("Dial timestamp is outside the accepted window");
  return dial;
}

/** 16 random bytes as hex. Distinguishes two dials sealed in the same millisecond. */
export function newNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
