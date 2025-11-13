import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';

import { MediaKeys } from './Types';

const CONTEXT_DERIVE_KEY = 'Internxt Meet Web App 2025-11-12 15:46:31 derive one key from two keys';
const CONTEXT_RATCHET = 'Internxt Meet Web App 2025-11-12 17:09:10 ratchet media key';

const AES_ALGORITHM = 'AES-GCM';
const AES_KEY_BIT_LENGTH = 256;
const KEY_FORMAT = 'raw';

export const IV_LEN_BYTES = 16;

export function hashData(data: string[]): Uint8Array {
    const hasher = blake3.create();

    for (const chunk of data) {
        hasher.update(utf8ToBytes(chunk));
    }

    return hasher.digest();
}

export function commitToMediaKey(keys: MediaKeys, commitment: Uint8Array): string {
    const hasher = blake3.create();

    hasher.update(commitment);
    hasher.update(keys.olmKey);
    hasher.update(keys.pqKey);
    hasher.update(new Uint8Array(keys.index));
    hasher.update(utf8ToBytes(keys.userID));
    const result = hasher.digest();

    return bytesToHex(result);
}

export async function hashKey(keys: MediaKeys): Promise<string> {
    const hasher = blake3.create();

    hasher.update(keys.olmKey);
    hasher.update(keys.pqKey);
    hasher.update(new Uint8Array(keys.index));
    hasher.update(utf8ToBytes(keys.userID));
    const result = hasher.digest();

    return bytesToHex(result);
}

export function getBitsFromString(byteLen: number, data: string): Uint8Array {
    return blake3(utf8ToBytes(data), { dkLen: byteLen });
}

export function deriveSymmetricCryptoKeyFromTwoKeys(key1: Uint8Array, key2: Uint8Array): Uint8Array {
    const combined_key = blake3(key1, { key: key2 });

    return blake3(combined_key, { context: utf8ToBytes(CONTEXT_DERIVE_KEY) });
}

export async function importSymmetricCryptoKey(keyData: Uint8Array | ArrayBuffer): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        KEY_FORMAT,
        new Uint8Array(keyData),
        {
            length: AES_KEY_BIT_LENGTH,
            name: AES_ALGORITHM,
        },
        true,
        [ 'encrypt', 'decrypt' ],
    );
}


export function ratchetMediaKey(key: MediaKeys): MediaKeys {
    const olmKey = blake3(key.olmKey, { context: utf8ToBytes(CONTEXT_RATCHET) });
    const pqKey = blake3(key.pqKey, { context: utf8ToBytes(CONTEXT_RATCHET) });
    const index = key.index + 1;
    const userID = key.userID;

    return { index, olmKey, pqKey, userID };
}

function createNISTbasedIV(freeField?: string): Uint8Array {
    try {
        if (!freeField) {
            return randomBytes(IV_LEN_BYTES);
        }

        const iv = new Uint8Array(16);
        const randFiled = randomBytes(12);

        iv.set(randFiled, 0);

        const freeFiledFixedLength = getBitsFromString(4, freeField);

        iv.set(freeFiledFixedLength, 12);

        return iv;
    } catch (error) {
        throw new Error(`Failed to create IV: ${error}`);
    }
}

export async function encryptSymmetrically(
        encryptionKey: CryptoKey,
        message: Uint8Array,
        additionalData: Uint8Array,
        freeField?: string,
): Promise<{ ciphertext: Uint8Array; iv: Uint8Array; }> {
    try {
        const iv = createNISTbasedIV(freeField);
        const encrypted = await crypto.subtle.encrypt({ additionalData: additionalData as BufferSource, iv: iv as BufferSource, name: AES_ALGORITHM }, encryptionKey, message as BufferSource);
        const ciphertext = new Uint8Array(encrypted);

        return { ciphertext, iv };
    } catch (error) {
        throw new Error(`Failed to encrypt symmetrically: ${error}`);
    }
}

export async function decryptSymmetrically(
        encryptionKey: CryptoKey,
        ciphertext: Uint8Array,
        iv: Uint8Array,
        additionalData: Uint8Array,
): Promise<Uint8Array> {
    try {
        const decrypted = await crypto.subtle.decrypt(
            { additionalData: additionalData as BufferSource, iv: iv as BufferSource, name: AES_ALGORITHM },
            encryptionKey,
            ciphertext as BufferSource,
        );

        return new Uint8Array(decrypted);

    } catch (error) {
        throw new Error(`Failed to decrypt symmetrically: ${error}`);
    }
}
