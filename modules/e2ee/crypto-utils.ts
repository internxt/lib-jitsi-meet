import kemBuilder from "@dashlane/pqc-kem-kyber512-browser";
import base64js from "base64-js";
import { Buffer } from "buffer";

const AES = "AES-GCM";
const HASH = "SHA-256";
const KDF = "HKDF";
const KEY_LEN = 256;

/**
 * Derives encryption key from the master key.
 *
 * @param {Uint8Array} olmKey - The olm key.
 * @param {Uint8Array} pqKey - The pq key.
 * @returns {Promise<CryptoKey>} Derived key.
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
 * Ratchets a key.
 * See https://tools.ietf.org/html/draft-omara-sframe-00#section-4.3.5.1
 *
 * @param {Uint8Array} key - The input key.
 * @returns {Promise<Uint8Array>} Ratched key.
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
 * Converts a raw key into a WebCrypto key object with default options.
 *
 * @param {ArrayBuffer} keyBytes - The raw key bytes.
 * @returns {Promise<CryptoKey>} WebCrypto key.
 */
export async function importKey(keyBytes: Uint8Array): Promise<CryptoKey> {
    try {
        return crypto.subtle.importKey("raw", keyBytes, KDF, false, [
            "deriveBits",
            "deriveKey",
        ]);
    } catch (error) {
        return Promise.reject(new Error(`Key import failed: ${error}`));
    }
}

/**
 * Converts a raw key into a WebCrypto AES key object.
 *
 * @param {ArrayBuffer} keyBytes - The raw key bytes.
 * @returns {Promise<CryptoKey>} WebCrypto key.
 */
export async function importAESKey(keyBytes: Uint8Array): Promise<CryptoKey> {
    try {
        return await crypto.subtle.importKey(
            "raw",
            keyBytes,
            {
                name: AES,
                length: KEY_LEN,
            },
            false,
            ["encrypt", "decrypt"],
        );
    } catch (error) {
        return Promise.reject(new Error(`AES key import failed: ${error}`));
    }
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
        const publicKeyBase64 = base64js.fromByteArray(publicKey);
        return { publicKeyBase64, privateKey };
    } catch (error) {
        return Promise.reject(
            new Error(`Kyber key generation failed: ${error}`),
        );
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
    if (!publicKyberKeyBase64?.length) {
        return Promise.reject(
            new Error(`Secret encapsulation failed: no public key given`),
        );
    }
    try {
        const kem = await kemBuilder();
        const participantEncapsulationKey: Uint8Array =
            base64js.toByteArray(publicKyberKeyBase64);
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
 * Performs decapsulation.
 * Returns a shared secret.
 *
 * @param {Uint8Array} ciphertextBase64 - The ciphertext.
 * @param {Uint8Array} privateKey - The private key.
 * @returns {Promise<{ sharedSecret: Uint8Array }>} Shared secret.
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
 * Derives one key from the two given keys.
 *
 * @param {Uint8Array} key1 - The first key.
 * @param {Uint8Array} key2 - The second key.
 * @returns {Uint8Array} Derived key.
 * @private
 */
async function deriveOneKey(
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
 * Decrypts message.
 *
 * @param {string} ciphertextBase64 - The ciphertext.
 * @param {string} ivBase64 - The IV.
 * @param {Uint8Array} key - The key.
 * @returns {Uint8Array} Decrypted message.
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

        const secretKey = await importAESKey(key);
        const additionalData = new TextEncoder().encode("PQ Key Info");

        const plaintext = await decryptData(
            iv,
            additionalData,
            secretKey,
            ciphertext,
        );

        return new Uint8Array(plaintext);
    } catch (error) {
        return Promise.reject(new Error(`PQ key decryption failed: ${error}`));
    }
}

/**
 * Encrypts the message.
 *
 * @param {Uint8Array} key - The key.
 * @param {Uint8Array} plaintext - The message.
 * @returns {Uint8Array, Uint8Array} Ciphertext.
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
        const secretKey = await importAESKey(key);

        const additionalData = new TextEncoder().encode("PQ Key Info");
        const ciphertext = new Uint8Array(
            await encryptData(iv, additionalData, secretKey, plaintext),
        );

        const ciphertextBase64 = base64js.fromByteArray(ciphertext);
        const ivBase64 = base64js.fromByteArray(iv);

        return { ciphertextBase64, ivBase64 };
    } catch (error) {
        return Promise.reject(new Error(`PQ key encryption failed: ${error}`));
    }
}

/**
 * Generates a new random key.
 *
 * @returns {Uint8Array} Key of KEY_LEN bits.
 */
export function generateKey() {
    return crypto.getRandomValues(new Uint8Array(KEY_LEN / 8));
}

/**
 * Decapsulates key and derives one key from the decapsulated one and the extra key given as input.
 *
 * @param {string} ciphertextBase64 - The Kyber ciphertext.
 * @param {Uint8Array} privateKey - The Kyber private key.
 * @param {Uint8Array} extraSecret - The additional secret.
 * @param {boolean} extraSecretGoesFirst - The flag to indicate if the extra key should go first.
 * @returns {Uint8Array} Derived key.
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
 * Symmetrically encrypts the given data
 *
 * @param {ArrayBuffer} iv - The IV vector.
 * @param {ArrayBuffer} additionalData - The additional data.
 * @param {ArrayBuffer} key - The encryption key/
 * @param {ArrayBuffer} data - The data to be encrypted.
 * @returns {Promise<ArrayBuffer>} Resulting ciphertext.
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

/**
 * Symmetrically decrypts the given data
 *
 * @param {ArrayBuffer} iv - The IV vector.
 * @param {ArrayBuffer} additionalData - The additional data.
 * @param {CryptoKey} key - The encryption key/
 * @param {ArrayBuffer} data - The data to be encrypted.
 * @returns {Promise<ArrayBuffer>} Resulting ciphertext.
 */
export function decryptData(iv, additionalData, key, data) {
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
