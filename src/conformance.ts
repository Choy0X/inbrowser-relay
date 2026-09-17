/**
 * A frozen wire-format test vector, asserted by both repositories.
 *
 * This file is the only thing holding the two halves of the relay together now
 * that they live in separate repositories. `protocol.ts` and `crypto.ts` used to
 * be byte-identical twins checked by a file comparison; across a repo boundary
 * that check is impossible, so correctness is pinned to observable output
 * instead of to source text.
 *
 * The vector below is a real sealed dial frame, produced once with a fixed IV.
 * Both sides assert that their own `deriveDialKey` + `openDial` recover
 * EXPECTED_DIAL from it. That catches every drift that actually matters:
 *
 *   - a changed HKDF info string or salt      -> key differs  -> tag fails
 *   - a changed cipher, key length or tag len -> decrypt fails
 *   - a changed frame layout                  -> decode fails
 *   - a changed JSON field name               -> assertion fails
 *
 * It cannot catch a change made identically and deliberately in both repos,
 * which is correct - that is a protocol revision, and it should bump
 * PROTOCOL_VERSION and regenerate this vector.
 *
 * If you are here because this assertion failed: the two repositories disagree
 * about the wire format. Do not "fix" it by regenerating the vector. Find which
 * side changed.
 *
 * Copy of this file also lives at `server/src/conformance.ts` in the app repo.
 */

/** The secret the vector was sealed under. Test-only; never use it anywhere real. */
export const VECTOR_SECRET = "inbrowser-relay-conformance-vector-secret-0001";

/**
 * A complete sealed dial frame: version byte, 12-byte IV, AES-256-GCM
 * ciphertext and tag. Generated with a fixed IV so the bytes are reproducible;
 * production always uses a random one.
 */
export const VECTOR_FRAME_HEX =
  "010102030405060708090a0b0c81ff68f20d1e839b07ba645012e8c183c9577f46815e36a433dbbd7aa7ccc1769" +
  "61bffe368946aa0b9302d5c1219b8e44d0efe2f3d050f5ea896b04252b4a342c8703a50f223ed036bb89582e18f" +
  "3c063e8ee194fc29fc15d41d78d0e97efd9b09f82c5610c8d07bc4cd7ff0dad32d0779bc13a318b37006e4b10d3" +
  "d688987ee438b9ca2b078fe08b187383ab6d0cee857bbde04f34bd9adc4443d8ad4dcac359321c6781aae8d57d5" +
  "80a3796aceb10f820087196ef6a3ed6f1c81c329856d4816f23fded9ab4a2386f2c52e4d3811fc1e6d12fa08c5e" +
  "5a5b479e24a04193d6e014f5fd2072089cc5489d2";

/** What opening VECTOR_FRAME_HEX must yield. */
export const EXPECTED_DIAL = {
  ts: 1700000000000,
  nonce: "00112233445566778899aabbccddeeff",
  protocol: "socks5",
  host: "proxy.example.com",
  port: 1080,
  username: "vector-user",
  password: "vector-pass",
  target: { host: "api.example.com", port: 443 },
} as const;

export function vectorFrame(): Uint8Array {
  const hex = VECTOR_FRAME_HEX;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
