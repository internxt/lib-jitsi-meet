import kemBuilder from "@dashlane/pqc-kem-kyber512-browser";
import base64js from "base64-js";
import { Buffer } from "buffer";

export const AES = "AES-GCM";
const HASH = "SHA-256";
const KDF = "HKDF";
const KEY_LEN = 256;

/**
 * Derives encryption key from the master key.
 * @param {CryptoKey} material - master key to derive from
 *
 * See https://tools.ietf.org/html/draft-omara-sframe-00#section-4.3.1
 */
export async function deriveKeys(
    olmKey: Uint8Array,
    pqKey: Uint8Array,
): Promise<CryptoKey> {
    try {
        const textEncoder = new TextEncoder();
        const data = new Uint8Array([...olmKey, ...pqKey]);
        const concatKey = await crypto.subtle.digest(HASH, data);
        const material = await importKey(new Uint8Array(concatKey));

        const encryptionKey = await crypto.subtle.deriveKey(
            {
                name: KDF,
                salt: textEncoder.encode("JFrameEncryptionKey"),
                hash: HASH,
                info: textEncoder.encode("JFrameInfo"),
            },
            material,
            {
                name: AES,
                length: KEY_LEN,
            },
            false,
            ["encrypt", "decrypt"],
        );

        return encryptionKey;
    } catch (error) {
        return Promise.reject(new Error(`Derive key failed: ${error}`));
    }
}

/**
 * Ratchets a key. See
 * https://tools.ietf.org/html/draft-omara-sframe-00#section-4.3.5.1
 *
 * @param {Uint8Array} key - base key material
 * @returns {Promise<Uint8Array>} - ratcheted key material
 */
export async function ratchet(keyBytes: Uint8Array): Promise<Uint8Array> {
    try {
        const material = await importKey(keyBytes);
        const textEncoder = new TextEncoder();
        const key = await crypto.subtle.deriveBits(
            {
                name: KDF,
                salt: textEncoder.encode("JFrameRatchetKey"),
                hash: HASH,
                info: textEncoder.encode("JFrameInfo"),
            },
            material,
            KEY_LEN,
        );
        return new Uint8Array(key);
    } catch (error) {
        return Promise.reject(new Error(`Ratchet failed: ${error}`));
    }
}

/**
 * Converts a raw key into a WebCrypto key object with default options
 *
 * @param {ArrayBuffer} keyBytes - raw key
 * @param {Array} keyUsages - key usages, see importKey documentation
 * @returns {Promise<CryptoKey>} - the WebCrypto key.
 */
export async function importKey(keyBytes: Uint8Array): Promise<CryptoKey> {
    try {
        return crypto.subtle.importKey("raw", keyBytes, KDF, false, [
            "deriveBits",
            "deriveKey",
        ]);
    } catch (error) {
        return Promise.reject(new Error(`Import key failed: ${error}`));
    }
}

/**
 * Encapsulates a key and returns a shared secret and its ciphertext
 *
 * @param {Uint8Array} publicKey - The public key.
 * @returns {Promise<{ sharedSecret: Uint8Array, ciphertext: Uint8Array }>}
 */
export async function generateKyberKeys(): Promise<{
    publicKeyBase64: string;
    privateKey: Uint8Array;
}> {
    try {
        const kem = await kemBuilder();
        const { publicKey, privateKey } = await kem.keypair();
        const publicKeyBase64 = base64js.fromByteArray(publicKey);
        return { publicKeyBase64, privateKey };
    } catch (error) {
        return Promise.reject(
            new Error(`Kyber key generation failed: ${error}`),
        );
    }
}

/**
 * Encapsulates a secret
 *
 * @param {Uint8Array} publicKeyBase64 - The public key.
 * @returns {Promise<{ sharedSecret: Uint8Array, ciphertextBase64: Uint8Array }>}
 */
export async function encapsulateSecret(publicKeyBase64: string): Promise<{
    encapsulatedBase64: string;
    sharedSecret: Uint8Array;
}> {
    if (!publicKeyBase64?.length) {
        return Promise.reject(
            new Error(`Secret encapsulation failed: no public key given`),
        );
    }
    try {
        const kem = await kemBuilder();
        const participantEncapsulationKey: Uint8Array =
            base64js.toByteArray(publicKeyBase64);
        const { ciphertext, sharedSecret } = await kem.encapsulate(
            participantEncapsulationKey,
        );
        const kyberCiphertext = base64js.fromByteArray(ciphertext);

        return { encapsulatedBase64: kyberCiphertext, sharedSecret };
    } catch (error) {
        return Promise.reject(
            new Error(`Secret encapsulation failed: ${error}`),
        );
    }
}

/**
 * Decapsulates a secret
 *
 * @param {Uint8Array} ciphertextBase64 - The ciphertext.
 * @param {Uint8Array} privateKey - The private key.
 * @returns {Promise<{ sharedSecret: Uint8Array }>}
 * @private
 */
export async function decapsulateSecret(
    ciphertextBase64: string,
    privateKey: Uint8Array,
): Promise<Uint8Array> {
    if (!ciphertextBase64?.length) {
        return Promise.reject(
            new Error(`Secret decapsulation failed: no ciphertext given`),
        );
    }
    if (!privateKey?.length) {
        return Promise.reject(
            new Error(`Secret decapsulation failed: no private key given`),
        );
    }
    try {
        const kem = await kemBuilder();
        const pqCiphertext: Uint8Array = base64js.toByteArray(ciphertextBase64);
        const { sharedSecret } = await kem.decapsulate(
            pqCiphertext,
            privateKey,
        );

        return sharedSecret;
    } catch (error) {
        return Promise.reject(
            new Error(`Secret decapsulation failed: ${error}`),
        );
    }
}

/**
 * Derives one key from two
 * @param {Uint8Array} key1 - The first key.
 * @param {Uint8Array} key2 - The second key.
 * @returns {Uint8Array}
 */
export async function deriveOneKey(
    key1: Uint8Array,
    key2: Uint8Array,
): Promise<Uint8Array> {
    if (!key1?.length || !key2?.length) {
        return Promise.reject(
            new Error(`Deriving one key failed: no keys given`),
        );
    }

    try {
        const data = new Uint8Array([...key1, ...key2]);
        const result = await crypto.subtle.digest(HASH, data);
        return new Uint8Array(result);
    } catch (error) {
        return Promise.reject(new Error(`Deriving one key failed: ${error}`));
    }
}

/**
 * Decrypts the current key information via pq channel for a given participant.
 *
 * @param {string} ciphertextBase64 - The ciphertext
 * @param {string} ivBase64 - The IV
 * @param {Uint8Array} key - Participant's pq session key
 * @returns {Uint8Array} - The encrypted text with the key information.
 * @private
 */
export async function decryptKeyInfoPQ(
    ciphertextBase64: string,
    ivBase64: string,
    key: Uint8Array,
): Promise<Uint8Array> {
    if (!ciphertextBase64?.length) {
        return Promise.reject(
            new Error("PQ key decryption failed: ciphertext is not given"),
        );
    }
    if (!ivBase64?.length) {
        return Promise.reject(
            new Error("PQ key decryption failed: iv is not given"),
        );
    }
    if (!key?.byteLength) {
        return Promise.reject(
            new Error("PQ key decryption failed: key is not given"),
        );
    }

    try {
        const ciphertext = Buffer.from(base64js.toByteArray(ciphertextBase64));
        const iv = base64js.toByteArray(ivBase64);

        const secretKey = await crypto.subtle.importKey(
            "raw",
            key,
            {
                name: AES,
                length: KEY_LEN,
            },
            false,
            ["encrypt", "decrypt"],
        );

        const plaintext = await crypto.subtle.decrypt(
            {
                name: AES,
                iv,
            },
            secretKey,
            ciphertext,
        );

        return new Uint8Array(plaintext);
    } catch (error) {
        return Promise.reject(new Error(`PQ key decryption failed: ${error}`));
    }
}

/**
 * Encrypts the current key information via pq channel for a given participant.
 *
 * @param {Uint8Array} key - Participant's pq session key
 * @returns {Uint8Array, Uint8Array} - The encrypted text with the key information.
 * @private
 */
export async function encryptKeyInfoPQ(
    key: Uint8Array,
    plaintext: Uint8Array,
): Promise<{ ciphertextBase64: string; ivBase64: string }> {
    if (!key?.length) {
        return Promise.reject(
            new Error("PQ key encryption failed: key is undefined"),
        );
    }
    if (!plaintext?.length) {
        return Promise.reject(
            new Error("PQ key encryption failed: message is undefined"),
        );
    }

    try {
        const iv = crypto.getRandomValues(new Uint8Array(16));
        const secretKey = await crypto.subtle.importKey(
            "raw",
            key,
            {
                name: AES,
                length: KEY_LEN,
            },
            false,
            ["encrypt", "decrypt"],
        );

        const ciphertext = new Uint8Array(
            await crypto.subtle.encrypt(
                { name: AES, iv },
                secretKey,
                plaintext,
            ),
        );

        const ciphertextBase64 = base64js.fromByteArray(ciphertext);
        const ivBase64 = base64js.fromByteArray(iv);

        return { ciphertextBase64, ivBase64 };
    } catch (error) {
        return Promise.reject(new Error(`PQ key encryption failed: ${error}`));
    }
}

/**
 * Generates a new random key
 *
 * @returns {Uint8Array}
 * @private
 */
export function generateKey() {
    return crypto.getRandomValues(new Uint8Array(KEY_LEN / 8));
}

/**
 * Decapsulates and derives one key
 *
 * @param {string} ciphertextBase64 - The Kyber ciphertext
 * @param {Uint8Array} privateKey - The Kyber private key
 * @param {Uint8Array} extraSecret - The additional secret
 * @returns {Uint8Array}
 * @private
 */
export async function decapsulateAndDeriveOneKey(
    ciphertextBase64: string,
    privateKey: Uint8Array,
    extraSecret: Uint8Array,
    extraSecretGoesFirst: boolean,
): Promise<Uint8Array> {
    try {
        const decapsulatedSecret = await decapsulateSecret(
            ciphertextBase64,
            privateKey,
        );

        if (extraSecretGoesFirst)
            return deriveOneKey(extraSecret, decapsulatedSecret);
        else return deriveOneKey(decapsulatedSecret, extraSecret);
    } catch (error) {
        return Promise.reject(
            new Error(`Decapsulate and derive secret failed: ${error}`),
        );
    }
}

/**
 * Encrypts the given frame
 * @param {RTCEncodedVideoFrame|RTCEncodedAudioFrame} encodedFrame
 * @returns {Uint8Array}
 * @private
 */
export function encryptData(iv, additionalData, key, data) {
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
