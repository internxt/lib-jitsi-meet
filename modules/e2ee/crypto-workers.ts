import { emojiMapping } from "./SAS";
import { hash, deriveKey, MediaKeys } from 'internxt-crypto';

export const RATCHET_CONTEXT =
    "LIB-JITSI-MEET; E2E with Kyber; 2025-04-04; Ratchet AES Encryption Key";


/**
 * Ratchets a key.
 *
 * @param {MediaKeys} key - The input key.
 * @returns {Promise<MediaKeys>} Ratched key.
 */
export async function ratchetMediaKey(key: MediaKeys): Promise<MediaKeys> {
    const olmKey = await deriveKey.deriveSymmetricKeyFromContext(RATCHET_CONTEXT, key.olmKey);
    const pqKey =  await deriveKey.deriveSymmetricKeyFromContext(RATCHET_CONTEXT, key.pqKey);
    const index = key.index + 1;
    const userID = key.userID;
    return {olmKey, pqKey, index, userID};
}


/**
 * Generates a SAS composed of emojies.
 * Borrowed from the Matrix JS SDK.
 *
 * @param {string} data - The string from which to generate SAS.
 * @returns {Promise<string[][]>} The SAS emojies.
 */
export async function generateEmojiSas(data: string): Promise<string[][]> {
    const sasBytes =  await hash.getBitsFromString(48, data);
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
