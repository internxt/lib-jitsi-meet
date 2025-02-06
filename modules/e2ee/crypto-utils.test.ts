import {
    generateKyberKeys,
    encapsulateSecret,
    decapsulateSecret,
    decryptKeyInfoPQ,
    encryptKeyInfoPQ,
    generateKey,
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
