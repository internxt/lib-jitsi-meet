export function deriveKeys(
    olmKey: Uint8Array,
    pqKey: Uint8Array,
): Promise<CryptoKey>;

export function ratchet(keyBytes: Uint8Array): Promise<Uint8Array>;

export function importKey(keyBytes: Uint8Array): Promise<CryptoKey>;

export function importAESKey(keyBytes: Uint8Array): Promise<CryptoKey>;

export function generateKyberKeys(): Promise<{
    publicKeyBase64: string;
    privateKey: Uint8Array;
}>;

export function encapsulateSecret(publicKyberKeyBase64: string): Promise<{
    encapsulatedBase64: string;
    sharedSecret: Uint8Array;
}>;

export function decapsulateSecret(
    ciphertextBase64: string,
    privateKey: Uint8Array,
): Promise<Uint8Array>;

export function decryptKeyInfoPQ(
    ciphertextBase64: string,
    ivBase64: string,
    key: Uint8Array,
): Promise<Uint8Array>;

export function encryptKeyInfoPQ(
    key: Uint8Array,
    plaintext: Uint8Array,
): Promise<{ ciphertextBase64: string; ivBase64: string }>;

export function decryptKeyInfoPQ(
    ciphertextBase64: string,
    ivBase64: string,
    key: Uint8Array,
): Promise<Uint8Array>;

export function generateKey(): Uint8Array;

export function decapsulateAndDeriveOneKey(
    ciphertextBase64: string,
    privateKey: Uint8Array,
    extraSecret: Uint8Array,
    extraSecretGoesFirst: boolean,
): Promise<Uint8Array>;

export function encryptData(
    iv: Uint8Array,
    additionalData: Uint8Array,
    key: CryptoKey,
    data: Uint8Array,
): Promise<ArrayBuffer>;
export function decryptData(
    iv: Uint8Array,
    additionalData: Uint8Array,
    key: CryptoKey,
    data: Uint8Array,
): Promise<ArrayBuffer>;
