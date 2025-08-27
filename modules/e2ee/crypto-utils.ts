import kemBuilder from "@dashlane/pqc-kem-kyber512-browser";
import { utils, symmetric } from 'internxt-crypto';

export function getError(method: string, error: any): Error {
    const errorMessage = `E2E: Function ${method} failed: ${error}`;
    return new Error(errorMessage);
}

/**
 * Generates Kyber key pair.
 *
 * @returns {Promise<{string, Uint8Array}>} A tuple containing public Kyber key in Base64 and private kyber key.
 */
export async function generateKyberKeys(): Promise<{
    publicKeyBase64: string;
    privateKey: Uint8Array;
}> {
    try {
        const kem = await kemBuilder();
        const { publicKey, privateKey } = await kem.keypair();
        const publicKeyBase64 = utils.uint8ArrayToBase64(publicKey);
        return { publicKeyBase64, privateKey };
    } catch (error) {
        return Promise.reject(getError("generateKyberKeys", error));
    }
}

/**
 * Performs encapsulation.
 * Returns a shared secret and teh corresponding ciphertext.
 *
 * @param {Uint8Array} publicKyberKeyBase64 - The public kyber key in Base64.
 * @returns {Promise<{ sharedSecret: Uint8Array, ciphertextBase64: Uint8Array }>} Tuple containing a shared secret and a ciphertext.
 */
export async function encapsulateSecret(publicKyberKeyBase64: string): Promise<{
    encapsulatedBase64: string;
    sharedSecret: Uint8Array;
}> {
    try {
        if (!publicKyberKeyBase64?.length) {
            throw Error(`No public key`);
        }
        const kem = await kemBuilder();
        const participantEncapsulationKey: Uint8Array =
            utils.base64ToUint8Array(publicKyberKeyBase64);
        const { ciphertext, sharedSecret } = await kem.encapsulate(
            participantEncapsulationKey,
        );
        const kyberCiphertext = utils.uint8ArrayToBase64(ciphertext);

        return { encapsulatedBase64: kyberCiphertext, sharedSecret };
    } catch (error) {
        return Promise.reject(getError("encapsulateSecret", error));
    }
}

/**
 * Performs decapsulation.
 * Returns a shared secret.
 *
 * @param {Uint8Array} ciphertextBase64 - The ciphertext.
 * @param {Uint8Array} privateKey - The private key.
 * @returns {Promise<Uint8Array>} Shared secret.
 */
export async function decapsulateSecret(
    ciphertextBase64: string,
    privateKey: Uint8Array,
): Promise<Uint8Array> {
    try {
        if (!ciphertextBase64?.length) {
            throw new Error(`No ciphertext`);
        }
        if (!privateKey?.length) {
            throw new Error(`No private key`);
        }

        const kem = await kemBuilder();
        const pqCiphertext: Uint8Array = utils.base64ToUint8Array(ciphertextBase64);
        const { sharedSecret } = await kem.decapsulate(
            pqCiphertext,
            privateKey,
        );

        return sharedSecret;
    } catch (error) {
        return Promise.reject(getError("decapsulateSecret", error));
    }
}

/**
 * Decrypts message.
 *
 * @param {string} ciphertextBase64 - The ciphertext.
 * @param {string} ivBase64 - The IV.
 * @param {CryptoKey} key - The key.
 * @returns {Uint8Array} Decrypted message.
 */
export async function decryptKeyInfoPQ(
    ciphertextBase64: string,
    key: CryptoKey,
): Promise<Uint8Array> {
    try {
        if (!ciphertextBase64?.length) {
            throw new Error("No ciphertext");
        }
        if (!key) {
            throw new Error("No key");
        }

        const ciphertext = symmetric.base64ToCiphertext(ciphertextBase64);
        const plaintext = await symmetric.decryptSymmetrically(key, ciphertext, "KeyInfoPQ");

        return plaintext;
    } catch (error) {
        return Promise.reject(getError("decryptKeyInfoPQ", error));
    }
}

/**
 * Encrypts the message.
 *
 * @param {Uint8Array} key - The key.
 * @param {Uint8Array} plaintext - The message.
 * @returns {string} Ciphertext.
 */
export async function encryptKeyInfoPQ(
    key: CryptoKey,
    plaintext: Uint8Array,
): Promise<string> {
    try {
        if (!key) {
            throw new Error("No key");
        }
        if (!plaintext?.length) {
            throw new Error("No message");
        }

        const result = await symmetric.encryptSymmetrically(key, plaintext, "KeyInfoPQ");
        const resultBase64 = symmetric.ciphertextToBase64(result);

        return resultBase64;
    } catch (error) {
        return Promise.reject(getError("encryptKeyInfoPQ", error));
    }
}

/**
 * Generates a new symmetric key.
 *
 * @returns {Uint8Array} The generted key.
 */
export function generateKey(): Uint8Array {
    return symmetric.genSymmetricKey();
}
