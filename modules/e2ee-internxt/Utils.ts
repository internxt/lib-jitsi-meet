import { base64 } from '@hexagon/base64';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

export function base64ToUint8Array(str: string): Uint8Array {
    return new Uint8Array(base64.toArrayBuffer(str));
}

export function uint8ArrayToBase64(array: Uint8Array): string {
    return base64.fromArrayBuffer(array.buffer as ArrayBuffer);
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
