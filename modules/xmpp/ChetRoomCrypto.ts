import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { concatBytes, randomBytes } from '@noble/ciphers/utils.js';

import { base64ToUint8Array, uint8ArrayToBase64 } from '../e2ee-internxt/Utils';

const CHAT_AUX = new TextEncoder().encode('Group Chat Message');
const NONCE_LEN_BYTES = 24;

export function encryptSymmetricallySync(
        message: string,
        encyptionKey: Uint8Array,
): string {
    try {
        console.info('E2E: ChatRoom encrypting message.');
        const messageBuffer = new TextEncoder().encode(message);
        const nonce = randomBytes(NONCE_LEN_BYTES);
        const chacha = xchacha20poly1305(encyptionKey, nonce, CHAT_AUX);
        const cipher = chacha.encrypt(messageBuffer);
        const cipherWithNonce = concatBytes(cipher, nonce);

        return uint8ArrayToBase64(cipherWithNonce);
    } catch (error) {
        throw new Error(`Failed to encrypt symmetrically: ${error}`);
    }
}

export function decryptSymmetricallySync(
        ciphertext: string,
        encryptionKey: Uint8Array,
): string {
    try {
        console.info('E2E: ChatRoom decrypting message.');
        const cipherBuffer = base64ToUint8Array(ciphertext);
        const cipher = cipherBuffer.slice(0, cipherBuffer.length - NONCE_LEN_BYTES);
        const nonce = cipherBuffer.slice(cipherBuffer.length - NONCE_LEN_BYTES);
        const chacha = xchacha20poly1305(encryptionKey, nonce, CHAT_AUX);
        const message = chacha.decrypt(cipher);

        return new TextDecoder().decode(message);

    } catch (error) {
        throw new Error(`Failed to decrypt symmetrically: ${error} for ciphertext: ${ciphertext}`);
    }
}
