import {
    generateKyberKeys,
    encapsulateSecret,
    decapsulateSecret,
    decryptKeyInfoPQ,
    encryptKeyInfoPQ,
    generateKey,
    decapsulateAndDeriveOneKey
} from "./crypto-utils";
import { describe, expect, it } from "vitest";

describe("Test Kyber KEM", () => {
    it("key encapsulation and decapsulation should work", async () => {
        const { publicKeyBase64, privateKey } = await generateKyberKeys();
        const { ciphertextBase64, sharedSecret } =
            await encapsulateSecret(publicKeyBase64);
        const decapsulatedSecret = await decapsulateSecret(
            ciphertextBase64,
            privateKey,
        );

        expect(decapsulatedSecret).toStrictEqual(sharedSecret);
    });

    it("key encapsulation should throw an error if no key is given", async () => {
        await expect(encapsulateSecret(undefined)).rejects.toThrowError(
            `Secret encapsulation failed: no public key given`,
        );
        await expect(encapsulateSecret("")).rejects.toThrowError(
            `Secret encapsulation failed: no public key given`,
        );
    });

    it("key decapsulation should throw an error for empty inputs", async () => {
        const { publicKeyBase64, privateKey } = await generateKyberKeys();
        const { ciphertextBase64, sharedSecret } =
            await encapsulateSecret(publicKeyBase64);

        await expect(
            decapsulateSecret(undefined, privateKey),
        ).rejects.toThrowError(
            `Secret decapsulation failed: no ciphertext given`,
        );
        await expect(decapsulateSecret("", privateKey)).rejects.toThrowError(
            `Secret decapsulation failed: no ciphertext given`,
        );

        await expect(
            decapsulateSecret(ciphertextBase64, undefined),
        ).rejects.toThrowError(
            `Secret decapsulation failed: no private key given`,
        );
        await expect(
            decapsulateSecret(ciphertextBase64, new Uint8Array()),
        ).rejects.toThrowError(
            `Secret decapsulation failed: no private key given`,
        );
    });

    it("encapsulate and decrypt should work", async () => {
       
        const { publicKeyBase64: publicKey1, privateKey: privateKey1 } = await generateKyberKeys();
        const { publicKeyBase64: publicKey2, privateKey: privateKey2 } = await generateKyberKeys();

        // session_init: user1 encapulates secret for user2
        const { ciphertextBase64: ciphertext1, sharedSecret: secret1 } =
                            await encapsulateSecret(publicKey2);

        // pq_session_init user2 encapsulates secret for user1 and derives key2               
        const { ciphertextBase64: ciphertext2, sharedSecret: secret2 } =
                            await encapsulateSecret(publicKey1);

        const key2 = await decapsulateAndDeriveOneKey(
                            ciphertext1,
                            privateKey2,
                            secret2,
                            true,
                        );

        // pq_session_ack user 1 derives key1
        const key1 = await decapsulateAndDeriveOneKey(
                                    ciphertext2,
                                    privateKey1,
                                    secret1,
                                    false,
                                );
                        

        expect(key1).toStrictEqual(key2);
    });
});

describe("Test key encryption", () => {
    it("key encryption and decryption should work", async () => {
        const key = generateKey();
        const message = generateKey();
        const { ciphertextBase64, ivBase64 } = await encryptKeyInfoPQ(
            key,
            message,
        );
        const decryptedMessage = await decryptKeyInfoPQ(
            ciphertextBase64,
            ivBase64,
            key,
        );

        expect(decryptedMessage).toStrictEqual(message);
    });
});

