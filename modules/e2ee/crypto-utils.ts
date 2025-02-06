import kemBuilder, { KEM } from "@dashlane/pqc-kem-kyber512-browser";
import base64js from "base64-js";
import { Buffer } from "buffer";
/**
 * Derives a set of keys from the master key.
 * @param {CryptoKey} material - master key to derive from
 *
 * See https://tools.ietf.org/html/draft-omara-sframe-00#section-4.3.1
 */
export async function deriveKeys(
    olmKey: Uint8Array,
    pqKey: Uint8Array,
): Promise<CryptoKey> {
    const textEncoder = new TextEncoder();
    const data = new Uint8Array([...olmKey, ...pqKey]);
    const concatKey = await crypto.subtle.digest("SHA-256", data);
    const material = await importKey(new Uint8Array(concatKey));

    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey#HKDF
    // https://developer.mozilla.org/en-US/docs/Web/API/HkdfParams
    const encryptionKey = await crypto.subtle.deriveKey(
        {
            name: "HKDF",
            salt: textEncoder.encode("JFrameEncryptionKey"),
            hash: "SHA-256",
            info: textEncoder.encode("JFrameInfo"),
        },
        material,
        {
            name: "AES-GCM",
            length: 256,
        },
        false,
        ["encrypt", "decrypt"],
    );

    return encryptionKey;
}

/**
 * Ratchets a key. See
 * https://tools.ietf.org/html/draft-omara-sframe-00#section-4.3.5.1
 * @param {CryptoKey} material - base key material
 * @returns {Promise<Uint8Array>} - ratcheted key material
 */
export async function ratchet(material: CryptoKey): Promise<Uint8Array> {
    const textEncoder = new TextEncoder();

    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveBits
    const key = await crypto.subtle.deriveBits(
        {
            name: "HKDF",
            salt: textEncoder.encode("JFrameRatchetKey"),
            hash: "SHA-256",
            info: textEncoder.encode("JFrameInfo"),
        },
        material,
        256,
    );
    return new Uint8Array(key);
}

/**
 * Converts a raw key into a WebCrypto key object with default options
 * suitable for our usage.
 * @param {ArrayBuffer} keyBytes - raw key
 * @param {Array} keyUsages - key usages, see importKey documentation
 * @returns {Promise<CryptoKey>} - the WebCrypto key.
 */
export async function importKey(keyBytes: Uint8Array): Promise<CryptoKey> {
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey

    return crypto.subtle.importKey("raw", keyBytes, "HKDF", false, [
        "deriveBits",
        "deriveKey",
    ]);
}

/**
 * Encapsulates a key and returns a shared secret and its ciphertext
 * @param {Uint8Array} publicKey - The public key.
 * @returns {Promise<{ sharedSecret: Uint8Array, ciphertext: Uint8Array }>}
 */
export async function generateKyberKeys(): Promise<{
    publicKeyBase64: String;
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
 * @param {Uint8Array} publicKeyBase64 - The public key.
 * @returns {Promise<{ sharedSecret: Uint8Array, ciphertextBase64: Uint8Array }>}
 */
export async function encapsulateSecret(publicKeyBase64: String): Promise<{
    ciphertextBase64: String;
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

        return { ciphertextBase64: kyberCiphertext, sharedSecret };
    } catch (error) {
        return Promise.reject(
            new Error(`Secret encapsulation failed: ${error}`),
        );
    }
}

/**
 * Decapsulates a secret
 * @param {Uint8Array} ciphertextBase64 - The ciphertext.
 * @param {Uint8Array} privateKey - The private key.
 * @returns {Promise<{ sharedSecret: Uint8Array }>}
 * @private
 */
export async function decapsulateSecret(
    ciphertextBase64: String,
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
export async function deriveOneKey(key1: Uint8Array, key2: Uint8Array): Promise<Uint8Array> {
    if (!key1?.length || !key2?.length) {
        return Promise.reject(new Error(`Deriving one key failed: no keys given`));
    }

    try {
        const key1Str = base64js.fromByteArray(key1);
        const key2Str = base64js.fromByteArray(key2);
        const data = key1Str + key2Str;
        const result = await sha256(data);
        return result;
    } catch (error) {
        return Promise.reject(new Error(`Deriving one key failed: ${error}`));
    }
}

/**
 * Computes sha256
 *
 * @param {String} input - The hash input
 * @returns {Uint8Array} - The computed sha256.
 * @private
 */
async function sha256(input: string): Promise<Uint8Array> {
    try {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);

    const hashBuffer = await crypto.subtle.digest("SHA-256", data); 
    return new Uint8Array(hashBuffer);
    } catch (error){
        return  Promise.reject(new Error(`sha256 failed: ${error}`));
    }
}

/**
 * Decrypts the current key information via pq channel for a given participant.
 *
 * @param {String} ciphertextBase64 - The ciphertext
 * @param {String} ivBase64 - The IV
 * @param {Uint8Array} key - Participant's pq session key
 * @returns {Uint8Array} - The encrypted text with the key information.
 * @private
 */
export async function decryptKeyInfoPQ(
    ciphertextBase64: String,
    ivBase64: String,
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
        const ciphertext = Buffer.from(
            base64js.toByteArray(ciphertextBase64),
            "base64",
        );
        const iv = base64js.toByteArray(ivBase64);

        const secretKey = await crypto.subtle.importKey(
            "raw",
            key,
            {
                name: "AES-GCM",
                length: 256,
            },
            false,
            ["encrypt", "decrypt"],
        );

        const plaintext = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
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
): Promise<{ ciphertextBase64: String; ivBase64: String }> {
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
                name: "AES-GCM",
                length: 256,
            },
            false,
            ["encrypt", "decrypt"],
        );

        const ciphertext = new Uint8Array(
            await crypto.subtle.encrypt(
                { name: "AES-GCM", iv },
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
 * Generates a new 256 bit random key.
 *
 * @returns {Uint8Array}
 * @private
 */
export function generateKey() {
    return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Decapsulates and derives one key
 *
 * @param {String} ciphertextBase64 - The Kyber ciphertext
 * @param {Uint8Array} privateKey - The Kyber private key
 * @param {Uint8Array} extraSecret - The additional secret
 * @returns {Uint8Array}
 * @private
 */
export async function decapsulateAndDeriveOneKey(
    ciphertextBase64: String,
    privateKey: Uint8Array,
    extraSecret: Uint8Array,
    extraSecretGoesFirst: boolean,
): Promise<Uint8Array> {
    try {
        const decapsulatedSecret = await decapsulateSecret(
            ciphertextBase64,
            privateKey,
        );

        if (extraSecretGoesFirst) return deriveOneKey(extraSecret, decapsulatedSecret);
        else return deriveOneKey(decapsulatedSecret, extraSecret);
    } catch (error) {
        return Promise.reject(
            new Error(`Decapsulate and derive secret failed: ${error}`),
        );
    }
}
