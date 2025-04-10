export const REQ_TIMEOUT = 20 * 1000;
export const IV_LENGTH = 16;
export const MEDIA_KEY_LEN = 32;
export const AUX = Uint8Array.from([
    80, 81, 32, 75, 101, 121, 32, 73, 110, 102, 111,
]); // "PQ Key Info"
export const AES = "AES-GCM";
export const AES_KEY_LEN = 256;
export const HASH_LEN = 256;

// We use a ringbuffer of keys so we can change them and still decode packets that were
// encrypted with an old key. We use a size of 16 which corresponds to the four bits
// in the frame trailer.
export const KEYRING_SIZE = 16;

// We copy the first bytes of the VP8 payload unencrypted.
// For keyframes this is 10 bytes, for non-keyframes (delta) 3. See
//   https://tools.ietf.org/html/rfc6386#section-9.1
// This allows the bridge to continue detecting keyframes (only one byte needed in the JVB)
// and is also a bit easier for the VP8 decoder (i.e. it generates funny garbage pictures
// instead of being unable to decode).
// This is a bit for show and we might want to reduce to 1 unconditionally in the final version.
//
// For audio (where frame.type is not set) we do not encrypt the opus TOC byte:
//   https://tools.ietf.org/html/rfc6716#section-3.1
export const VIDEO_UNENCRYPTED_BYTES = {
    key: 10,
    delta: 3,
};

export const SAS_LEN = 48;

export const DERIVE_CONTEXT =
    "LIB-JITSI-MEET; E2E with Kyber; 2025-04-04; Derive AES Encryption Key from two keys";
export const RATCHET_CONTEXT =
    "LIB-JITSI-MEET; E2E with Kyber; 2025-04-04; Ratchet AES Encryption Key";
export const MEDIA_KEY_COMMITMENT_PREFIX =
    "LIB-JITSI-MEET; E2E with Kyber; 2025-04-04; Commit to media key shares";
export const KEY_HASH_PREFIX =
    "LIB-JITSI-MEET; E2E with Kyber; 2025-04-04; Hash current encryption keys of the participant";
export const IDENTITY_KEYS_PREFIX =
    "LIB-JITSI-MEET; E2E with Kyber; 2025-04-04; Hash identity keys of the participant";
