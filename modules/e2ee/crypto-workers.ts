import {
    SAS_LEN,
    RATCHET_CONTEXT,
    IDENTITY_KEYS_PREFIX,
    KEY_HASH_PREFIX,
} from "./Constants";
import { emojiMapping } from "./SAS";
import { hash, deriveKey, MediaKeys, keystoreCrypto } from 'internxt-crypto';

/**
 * Ratchets a key.
 *
 * @param {Uint8Array} keyBytes - The input key.
 * @returns {Promise<Uint8Array>} Ratched key.
 */
export async function ratchetKey(keyBytes: Uint8Array): Promise<Uint8Array> {
    return await deriveKey.deriveSymmetricKeyFromContext(RATCHET_CONTEXT, keyBytes);
}

export async function hashKeysOfParticipant(
    key: MediaKeys,
    keyCommitment: string,
): Promise<string> {
    const keyBase64 = await keystoreCrypto.mediaKeysToBase64(key);
    return hash.hashData([
        KEY_HASH_PREFIX,
        keyBase64,
        keyCommitment]
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
    return await hash.hashData([
        IDENTITY_KEYS_PREFIX,
        participantID,
        publicKyberKey,
        publicKey]);
}
/**
 * Generates a SAS composed of emojies.
 * Borrowed from the Matrix JS SDK.
 *
 * @param {string} data - The string from which to generate SAS.
 * @returns {Promise<string[][]>} The SAS emojies.
 */
export async function generateEmojiSas(data: string): Promise<string[][]> {
    const sasBytes =  await hash.getBitsFromString(SAS_LEN, data);
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
