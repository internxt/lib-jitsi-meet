import kemBuilder from "@dashlane/pqc-kem-kyber512-browser";
import * as base64js from "base64-js";

const AES = "AES-GCM";
const HASH = "SHA-256";
const KDF = "HKDF";
const KEY_LEN = 256;
const IV_LENGTH = 16;

/**
 * Derives an AES encryption key from two keys.
 *
 * @param {Uint8Array} key1 - The first key.
 * @param {Uint8Array} key2 - The second key.
 * @returns {Promise<CryptoKey>} Derived key.
 */
export async function deriveEncryptionKey(
    key1: Uint8Array,
    key2: Uint8Array,
): Promise<CryptoKey> {
    try {
        const textEncoder = new TextEncoder();
        const data = new Uint8Array(key1.length + key2.length);
        data.set(key1, 0);
        data.set(key2, key1.length);
        const concatKey = await crypto.subtle.digest(HASH, data);
        const material = await importKey(new Uint8Array(concatKey));

        const encryptionKey = await crypto.subtle.deriveKey(
            {
                name: KDF,
                salt: textEncoder.encode("Derive_AES_Encryption_Key"),
                hash: HASH,
                info: textEncoder.encode("AES_Encryption_Key_Info"),
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
        return Promise.reject(new Error(`AES key derivation failed: ${error}`));
    }
}

/**
 * Ratchets a key.
 * See https://tools.ietf.org/html/draft-omara-sframe-00#section-4.3.5.1
 *
 * @param {Uint8Array} keyBytes - The input key.
 * @returns {Promise<Uint8Array>} Ratched key.
 */
export async function ratchetKey(keyBytes: Uint8Array): Promise<Uint8Array> {
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
async function importKey(keyBytes: Uint8Array): Promise<CryptoKey> {
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
    if (!ciphertextBase64?.length) {
        return Promise.reject(
            new Error("PQ key decryption failed: ciphertext is not given"),
        );
    }
    if (!key) {
        return Promise.reject(
            new Error("PQ key decryption failed: key is not given"),
        );
    }

    try {
        const ciphertext = base64js.toByteArray(ciphertextBase64);
        const iv = ciphertext.slice(0, IV_LENGTH);
        const cipher = ciphertext.slice(IV_LENGTH);

        const additionalData = new TextEncoder().encode("PQ Key Info");

        const plaintext = await decryptData(iv, additionalData, key, cipher);

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
 * @returns {string} Ciphertext.
 */
export async function encryptKeyInfoPQ(
    key: CryptoKey,
    plaintext: Uint8Array,
): Promise<string> {
    if (!key) {
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
        const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
        const additionalData = new TextEncoder().encode("PQ Key Info");

        const ciphertext = new Uint8Array(
            await encryptData(iv, additionalData, key, plaintext),
        );

        const result = new Uint8Array(IV_LENGTH + ciphertext.length);
        result.set(iv, 0);
        result.set(ciphertext, IV_LENGTH);

        const resultBase64 = base64js.fromByteArray(result);

        return resultBase64;
    } catch (error) {
        return Promise.reject(new Error(`PQ key encryption failed: ${error}`));
    }
}

/**
 * Generates a new random key.
 *
 * @returns {Uint8Array} Key of KEY_LEN bits.
 */
export function generateKey(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(KEY_LEN / 8));
}

/**
 * Decapsulates key and derives one key from the decapsulated one and the extra key given as input.
 *
 * @param {string} ciphertextBase64 - The Kyber ciphertext.
 * @param {Uint8Array} privateKey - The Kyber private key.
 * @param {Uint8Array} extraSecret - The additional secret.
 * @param {boolean} extraSecretGoesFirst - The flag to indicate if the extra key should go first.
 * @returns {CryptoKey} Derived key.
 */
export async function decapsulateAndDeriveOneKey(
    ciphertextBase64: string,
    privateKey: Uint8Array,
    extraSecret: Uint8Array,
    extraSecretGoesFirst: boolean,
): Promise<CryptoKey> {
    try {
        const decapsulatedSecret = await decapsulateSecret(
            ciphertextBase64,
            privateKey,
        );

        if (extraSecretGoesFirst)
            return deriveEncryptionKey(extraSecret, decapsulatedSecret);
        else return deriveEncryptionKey(decapsulatedSecret, extraSecret);
    } catch (error) {
        return Promise.reject(
            new Error(`Decapsulate and derive secret failed: ${error}`),
        );
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
