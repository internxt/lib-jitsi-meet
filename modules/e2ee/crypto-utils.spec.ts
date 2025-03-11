import {
    generateKyberKeys,
    encapsulateSecret,
    decapsulateSecret,
    decryptKeyInfoPQ,
    encryptKeyInfoPQ,
    generateKey,
} from "./crypto-utils";

import { deriveEncryptionKey } from "./crypto-workers";

describe("Test Kyber KEM", () => {
    it("key encapsulation and decapsulation should work", async () => {
        const { publicKeyBase64, privateKey } = await generateKyberKeys();
        const { encapsulatedBase64: ciphertextBase64, sharedSecret } =
            await encapsulateSecret(publicKeyBase64);
        const decapsulatedSecret = await decapsulateSecret(
            ciphertextBase64,
            privateKey,
        );

        expect(decapsulatedSecret).toEqual(sharedSecret);
    });

    it("key encapsulation should throw an error if no key is given", async () => {
        await expectAsync(encapsulateSecret("")).toBeRejectedWithError(
            Error,
            `Secret encapsulation failed: no public key given`,
        );
    });

    it("key decapsulation should throw an error for empty inputs", async () => {
        const { publicKeyBase64, privateKey } = await generateKyberKeys();
        const { encapsulatedBase64: ciphertextBase64 } =
            await encapsulateSecret(publicKeyBase64);

        await expectAsync(
            decapsulateSecret("", privateKey),
        ).toBeRejectedWithError(
            Error,
            `Secret decapsulation failed: no ciphertext given`,
        );

        await expectAsync(
            decapsulateSecret(ciphertextBase64, new Uint8Array()),
        ).toBeRejectedWithError(
            Error,
            `Secret decapsulation failed: no private key given`,
        );
    });

    it("encapsulate and decrypt should work", async () => {
        const { publicKeyBase64: publicKey1, privateKey: privateKey1 } =
            await generateKyberKeys();
        const { publicKeyBase64: publicKey2, privateKey: privateKey2 } =
            await generateKyberKeys();

        // session_init: user1 encapulates secret for user2
        const { encapsulatedBase64: ciphertext1, sharedSecret: secret1 } =
            await encapsulateSecret(publicKey2);

        // pq_session_init user2 encapsulates secret for user1 and derives key2
        const { encapsulatedBase64: ciphertext2, sharedSecret: secret2 } =
            await encapsulateSecret(publicKey1);

        const decapsulatedSecret2 = await decapsulateSecret(
            ciphertext1,
            privateKey2,
        );

        const key2 = await deriveEncryptionKey(secret2, decapsulatedSecret2);

        // pq_session_ack user 1 derives key1
        const decapsulatedSecret1 = await decapsulateSecret(
            ciphertext2,
            privateKey1,
        );
        const key1 = await deriveEncryptionKey(decapsulatedSecret1, secret1);

        expect(key1).toEqual(key2);
    });
});

describe("Test key encryption", () => {
    it("key encryption and decryption should work", async () => {
        const keyBytes = generateKey();
        const key = await crypto.subtle.importKey(
            "raw",
            keyBytes,
            {
                name: "AES-GCM",
                length: 256,
            },
            false,
            ["encrypt", "decrypt"],
        );
        const message = generateKey();
        const ciphertextBase64 = await encryptKeyInfoPQ(key, message);
        const decryptedMessage = await decryptKeyInfoPQ(ciphertextBase64, key);

        expect(decryptedMessage).toEqual(message);
    });
});
