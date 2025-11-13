import { base64 } from '@hexagon/base64';
import { concatBytes, randomBytes } from '@noble/hashes/utils.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import { IV_LEN_BYTES } from './CryptoUtils';

const AES_KEY_BYTE_LENGTH = 32;


export function base64ToUint8Array(str: string): Uint8Array {
    return new Uint8Array(base64.toArrayBuffer(str));
}

export function uint8ArrayToBase64(array: Uint8Array): string {
    return base64.fromArrayBuffer(array.buffer as ArrayBuffer);
}

export function ciphertextToBase64(ciphertext: Uint8Array, iv: Uint8Array): string {
    const bigArray = concatBytes(ciphertext, iv);

    return uint8ArrayToBase64(bigArray);
}

export function base64ToCiphertext(ciphertextBase64: string): { ciphertext: Uint8Array; iv: Uint8Array; } {
    const combined = base64ToUint8Array(ciphertextBase64);
    const ciphertext = combined.slice(0, combined.length - IV_LEN_BYTES);
    const iv = combined.slice(combined.length - IV_LEN_BYTES);

    return { ciphertext, iv };
}

export function encapsulateKyber(publicKey: Uint8Array): {
    cipherText: Uint8Array;
    sharedSecret: Uint8Array;
} {
    return ml_kem768.encapsulate(publicKey);
}

export function decapsulateKyber(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array {
    return ml_kem768.decapsulate(cipherText, secretKey);
}

export function generateKyberKeys(): {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
} {
    return ml_kem768.keygen();
}

export function genSymmetricKey(): Uint8Array {
    return randomBytes(AES_KEY_BYTE_LENGTH);
}
