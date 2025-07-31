import { createBLAKE3 } from "hash-wasm";
import {
    AES,
    AES_KEY_LEN,
    HASH_LEN,
    SAS_LEN,
    RATCHET_CONTEXT,
    DERIVE_CONTEXT,
    MEDIA_KEY_COMMITMENT_PREFIX,
    IDENTITY_KEYS_PREFIX,
    KEY_HASH_PREFIX,
} from "./Constants";
import { emojiMapping } from "./SAS";
import { MediaKey } from "./Types";

/**
 * Computes hash.
 *
 * @param {string} context - The context value.
 * @param {string} participantID - The string value.
 * @param {Uint8Array} key1 - The first key.
 * @param {Uint8Array} key2 - The second key.
 * @param {number} index - The index.
 * @returns {Promise<string>} Computed hash.
 */
async function computeHash(
    context: string,
    participantID: string,
    key1: Uint8Array | string,
    key2: Uint8Array | string,
    index: number = -1,
    keyCommitment: string = "NoKeyCommitment",
): Promise<string> {
    try {
        const hasher = await createBLAKE3(HASH_LEN);
        hasher.init();
        hasher.update(context);
        hasher.update(participantID);
        hasher.update(key1);
        hasher.update(key2);
        hasher.update("index=" + index);
        hasher.update(keyCommitment);

        return hasher.digest();
    } catch (error) {
        return Promise.reject(
            new Error(`E2E: Hash computation failed: ${error}`),
        );
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
        const hasher = await createBLAKE3(HASH_LEN, key1);
        hasher.init();
        hasher.update(DERIVE_CONTEXT);
        hasher.update(key2);
        const keyBytes = hasher.digest("binary");

        return crypto.subtle.importKey(
            "raw",
            keyBytes,
            {
                name: AES,
                length: AES_KEY_LEN,
            },
            false,
            ["encrypt", "decrypt"],
        );
    } catch (error) {
        return Promise.reject(
            new Error(`E2E: Key derivation failed: ${error}`),
        );
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
        const hasher = await createBLAKE3(AES_KEY_LEN, keyBytes);
        hasher.init();
        hasher.update(RATCHET_CONTEXT);
        return hasher.digest("binary");
    } catch (error) {
        return Promise.reject(new Error(`E2E: Ratchet failed: ${error}`));
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

export async function commitToMediaKeyShares(
    participantID: string,
    key: MediaKey,
): Promise<string> {
    return computeHash(
        MEDIA_KEY_COMMITMENT_PREFIX,
        participantID,
        key.olmKey,
        key.pqKey,
        key.index,
    );
}

export async function hashKeysOfParticipant(
    participantID: string,
    keyOlm: Uint8Array,
    keyPQ: Uint8Array,
    index: number,
    keyCommitment: string,
): Promise<string> {
    return computeHash(
        KEY_HASH_PREFIX,
        participantID,
        keyOlm,
        keyPQ,
        index,
        keyCommitment,
    );
}

/**
 * Computes commitment to two strings.
 *
 * @param {string} value1 - The first value.
 * @param {string} value2 - The second value.
 * @returns {Promise<string>} Computed commitment.
 */
export async function commitToIdentityKeys(
    participantID: string,
    publicKyberKey: string,
    publicKey: string,
): Promise<string> {
    return computeHash(
        IDENTITY_KEYS_PREFIX,
        participantID,
        publicKyberKey,
        publicKey,
    );
}
/**
 * Generates a SAS composed of emojies.
 * Borrowed from the Matrix JS SDK.
 *
 * @param {string} data - The string from which to generate SAS.
 * @returns {Promise<string[][]>} The SAS emojies.
 */
export async function generateEmojiSas(data: string): Promise<string[][]> {
    const hasher = await createBLAKE3(SAS_LEN);
    hasher.init();
    hasher.update(data);
    const sasBytes = hasher.digest("binary");
    // Just like base64.
    const emojis = [
        sasBytes[0] >> 2,
        ((sasBytes[0] & 0x3) << 4) | (sasBytes[1] >> 4),
        ((sasBytes[1] & 0xf) << 2) | (sasBytes[2] >> 6),
        sasBytes[2] & 0x3f,
        sasBytes[3] >> 2,
        ((sasBytes[3] & 0x3) << 4) | (sasBytes[4] >> 4),
        ((sasBytes[4] & 0xf) << 2) | (sasBytes[5] >> 6),
    ];

    return emojis.map((num) => emojiMapping[num]);
}

export function logInfo(message: string) {
    console.info(`E2E: ${message}`);
}

export function logWarning(message: string) {
    console.warn(`E2E: ${message}`);
}

export function logError(message: string) {
    console.error(`E2E: ${message}`);
}
