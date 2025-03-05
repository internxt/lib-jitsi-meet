import { createBLAKE3 } from "hash-wasm";

const SAS_LEN = 48;
const KDF = "HKDF";
const AES = "AES-GCM";
const HASH = "SHA-256";
const AES_KEY_LEN = 256;
const COMMITMENT_LEN = 256;
const KDF_SALT_DERIVE_KEY = new Uint8Array([
    68, 101, 114, 105, 118, 101, 95, 65, 69, 83, 95, 69, 110, 99, 114, 121, 112,
    116, 105, 111, 110, 95, 75, 101, 121,
]); // "Derive_AES_Encryption_Key"
const KDF_INFO_DERIVE_KEY = new Uint8Array([
    65, 69, 83, 95, 69, 110, 99, 114, 121, 112, 116, 105, 111, 110, 95, 75, 101,
    121, 95, 73, 110, 102, 111,
]); // "AES_Encryption_Key_Info"
const DERIVE_BITS_SALT = new Uint8Array([
    74, 70, 114, 97, 109, 101, 82, 97, 116, 99, 104, 101, 116, 75, 101, 121,
]); // "JFrameRatchetKey"
const DERIVE_BITS_INFO = new Uint8Array([
    74, 70, 114, 97, 109, 101, 73, 110, 102, 111,
]); // "JFrameInfo"

/**
 * Computes commitment to the keys.
 *
 * @param {string} publicKyberKey - The public keyber key.
 * @param {string} curve25519Key - The public curve25519 key.
 * @returns {Promise<string>} Computed commitment.
 */
export async function computeKeyCommitment(
    publicKyberKey: string,
    curve25519Key: string,
): Promise<string> {
        const hasher = await createBLAKE3(COMMITMENT_LEN);
        hasher.init();
        hasher.update(publicKyberKey);
        hasher.update(curve25519Key);
        return hasher.digest();
}

/**
 * Converts a raw key into a WebCrypto key object suitable for key derivation.
 *
 * @param {ArrayBuffer} keyBytes - The raw key bytes.
 * @returns {Promise<CryptoKey>} WebCrypto key.
 */
async function importKey(keyBytes: Uint8Array): Promise<CryptoKey> {
    try {
        return crypto.subtle.importKey("raw", keyBytes, KDF, false, [
            "deriveBits",
            "deriveKey",
        ]);
    } catch (error) {
        return Promise.reject(new Error(`Key import failed: ${error}`));
    }
}

/**
 * Derives an AES encryption key from two keys.
 *
 * @param {Uint8Array} key1 - The first key.
 * @param {Uint8Array} key2 - The second key.
 * @returns {Promise<{ encryptionKey: CryptoKey; hash: Uint8Array }>} Derived key and hash.
 */
export async function deriveEncryptionKey(
    key1: Uint8Array,
    key2: Uint8Array,
): Promise<{ encryptionKey: CryptoKey; hash: Uint8Array }> {
    try {
        const hasher = await createBLAKE3(AES_KEY_LEN);
        hasher.init();
        hasher.update(key1);
        hasher.update(key2);
        const hash = hasher.digest("binary");
        const material = await importKey(hash);

        const encryptionKey = await crypto.subtle.deriveKey(
            {
                name: KDF,
                salt: KDF_SALT_DERIVE_KEY,
                hash: HASH,
                info: KDF_INFO_DERIVE_KEY,
            },
            material,
            {
                name: AES,
                length: AES_KEY_LEN,
            },
            false,
            ["encrypt", "decrypt"],
        );

        return { encryptionKey, hash };
    } catch (error) {
        return Promise.reject(new Error(`AES key derivation failed: ${error}`));
    }
}

/**
 * Ratchets a key.
 * See https://tools.ietf.org/html/draft-omara-sframe-00#section-4.3.5.1
 *
 * @param {Uint8Array} keyBytes - The input key.
 * @returns {Promise<Uint8Array>} Ratched key.
 */
export async function ratchetKey(keyBytes: Uint8Array): Promise<Uint8Array> {
    try {
        const material = await importKey(keyBytes);
        const key = await crypto.subtle.deriveBits(
            {
                name: KDF,
                salt: DERIVE_BITS_SALT,
                hash: HASH,
                info: DERIVE_BITS_INFO,
            },
            material,
            AES_KEY_LEN,
        );
        return new Uint8Array(key);
    } catch (error) {
        return Promise.reject(new Error(`Ratchet failed: ${error}`));
    }
}

/**
 * Symmetrically encrypts the given data
 *
 * @param {Uint8Array} iv - The IV vector.
 * @param {Uint8Array} additionalData - The additional data.
 * @param {CryptoKey} key - The encryption key/
 * @param {Uint8Array} data - The data to be encrypted.
 * @returns {Promise<ArrayBuffer>} Resulting ciphertext.
 */
export function encryptData(
    iv: Uint8Array,
    additionalData: Uint8Array,
    key: CryptoKey,
    data: Uint8Array,
): Promise<ArrayBuffer> {
    return crypto.subtle.encrypt(
        {
            name: AES,
            iv,
            additionalData,
        },
        key,
        data,
    );
}

/**
 * Symmetrically decrypts the given data
 *
 * @param {Uint8Array} iv - The IV vector.
 * @param {Uint8Array} additionalData - The additional data.
 * @param {CryptoKey} key - The encryption key/
 * @param {ArrayBuffer} data - The data to be encrypted.
 * @returns {Promise<ArrayBuffer>} Resulting ciphertext.
 */
export function decryptData(
    iv: Uint8Array,
    additionalData: Uint8Array,
    key: CryptoKey,
    data: Uint8Array,
): Promise<ArrayBuffer> {
    return crypto.subtle.decrypt(
        {
            name: AES,
            iv,
            additionalData,
        },
        key,
        data,
    );
}

/**
 * Derives SAS bytes.
 *
 * @param {string} data - The input data.
 * @returns {Promise<Uint8Array>} Computed SAS bytes.
 */
export async function deriveSASBytes(data: string): Promise<Uint8Array> {
    const hasher = await createBLAKE3(SAS_LEN);
    hasher.init();
    hasher.update(data);
    return hasher.digest("binary");
}
