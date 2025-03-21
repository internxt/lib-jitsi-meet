import { createKeccak, createHMAC } from "hash-wasm";
const AES = "AES-GCM";
const AES_KEY_LEN = 256;
const HASH_LEN = 256;

/**
 * Computes commitment to two strings.
 *
 * @param {string} value1 - The first value.
 * @param {string|Uint8Array} value2 - The second value.
 * @returns {Promise<string>} Computed commitment.
 */
export async function computeCommitment(
    value1: string,
    value2: string|Uint8Array,
): Promise<string> {
    try {
        const hasher = await createKeccak(HASH_LEN);
        hasher.init();
        hasher.update(value1);
        hasher.update(value2);
        return hasher.digest();
    } catch (error) {
        return Promise.reject(
            new Error(`Commitment computation failed: ${error}`),
        );
    }
}

/**
 * Computes hash.
 *
 * @param {Uint8Array} value1 - The first value.
 * @param {Uint8Array} value2 - The second value.
 * @param {string} value3 - The thirs value.
 * @param {number} value4 - The forth value.
 * @returns {Promise<string>} Computed hash.
 */
export async function computeHash(
    value1: Uint8Array,
    value2: Uint8Array,
    value3: string,
    value4: number,
): Promise<string> {
    try {
        const hasher = await createKeccak(HASH_LEN);
        hasher.init();
        hasher.update(value1);
        hasher.update(value2);
        hasher.update(value3);
        hasher.update("index=" + value4);
        return hasher.digest();
    } catch (error) {
        return Promise.reject(new Error(`Hash computation failed: ${error}`));
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
): Promise<CryptoKey> {
    try {
        const key = new Uint8Array(key1.length + key2.length);
        key.set(key1, 0);
        key.set(key2, key1.length);

        const hasher = createKeccak(HASH_LEN);
        const hmac = await createHMAC(hasher, key);
        hmac.update("Derive_AES_Encryption_Key");
        const keyBytes = hmac.digest("binary");

        const encryptionKey = await crypto.subtle.importKey(
            "raw",
            keyBytes,
            {
                name: "AES-GCM",
                length: 256,
            },
            false,
            ["encrypt", "decrypt"],
        );

        return encryptionKey;
    } catch (error) {
        return Promise.reject(new Error(`Key derivation failed: ${error}`));
    }
}

/**
 * Ratchets a key.
 *
 * @param {Uint8Array} keyBytes - The input key.
 * @returns {Promise<Uint8Array>} Ratched key.
 */
export async function ratchetKey(keyBytes: Uint8Array): Promise<Uint8Array> {
    try {
        const hasher = createKeccak(AES_KEY_LEN);
        const hmac = await createHMAC(hasher, keyBytes);
        hmac.update("JFrameInfo");
        return hmac.digest("binary");
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
