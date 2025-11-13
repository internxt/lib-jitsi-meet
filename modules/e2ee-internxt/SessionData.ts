import { Account, Session } from 'vodozemac-wasm';

import { decryptSymmetrically, deriveSymmetricCryptoKeyFromTwoKeys, encryptSymmetrically, hashKey, importSymmetricCryptoKey } from './CryptoUtils';
import {
    KeyInfo,
    MediaKeys,
    NORMAL_MESSAGE,
    PREKEY_MESSAGE,
    PROTOCOL_STATUS,
    ProtocolStatus,
} from './Types';
import { base64ToCiphertext, base64ToUint8Array, ciphertextToBase64, encapsulateKyber, uint8ArrayToBase64 } from './Utils';


const AUX = new Uint8Array([ 1, 2, 3 ]);

export class SessionData {
    private status: ProtocolStatus;
    private commitment: string;
    private keyToSend: MediaKeys;
    private session?: Session;
    private pqSessionKey?: CryptoKey;
    private kemSecret: Uint8Array;

    constructor(key: MediaKeys) {
        this.status = PROTOCOL_STATUS.READY_TO_START;
        this.keyToSend = key;
    }

    indexChanged(key: MediaKeys): boolean {
        return this.keyToSend.index !== key.index;
    }

    createInboundOLMchannel(
            account: Account,
            publicKey: string,
            ciphertext: string,
    ) {
        const { plaintext, session } = account.create_inbound_session(
            publicKey,
            PREKEY_MESSAGE,
            ciphertext,
        );

        this.session = session;
        this.commitment = new TextDecoder().decode(plaintext);
    }

    createOutboundOLMchannel(
            account: Account,
            publicKey: string,
            otKey: string,
            commitment: string,
    ) {
        this.commitment = commitment;
        this.session = account.create_outbound_session(publicKey, otKey);
    }

    encapsulate(publicKyberKey: string): string {
        const publicKey = base64ToUint8Array(publicKyberKey);
        const { cipherText, sharedSecret } = encapsulateKyber(publicKey);

        this.kemSecret = sharedSecret;

        return uint8ArrayToBase64(cipherText);
    }

    isDone(): boolean {
        return (
            this.status === PROTOCOL_STATUS.DONE
            || this.status === PROTOCOL_STATUS.WAITING_DONE
        );
    }

    validateStatus(status: ProtocolStatus) {
        if (this.status !== status)
            throw new Error(
                `Protocol status is ${this.status} but expected ${status}.`,
            );
    }

    async validateCommitment(key: MediaKeys) {
        const commitment = await hashKey(key);

        if (this.commitment !== commitment)
            throw new Error('Keys do not match the commitment.');
    }

    setStatus(status: ProtocolStatus) {
        if (this.status === PROTOCOL_STATUS.TERMINATED) {
            throw new Error('Terminated while processing.');
        }
        this.status = status;
    }

    clearSession() {
        this.status = PROTOCOL_STATUS.TERMINATED;
        this.session?.free();
    }

    setDone() {
        this.status = PROTOCOL_STATUS.DONE;
        this.commitment = '';
        this.kemSecret = new Uint8Array();
        this.keyToSend = {
            index: -1,
            olmKey: new Uint8Array(),
            pqKey: new Uint8Array(),
            userID: '',
        };
    }

    async keyCommitment(): Promise<string> {
        return hashKey(this.keyToSend);
    }

    async createKeyInfoMessage(key: MediaKeys): Promise<KeyInfo> {
        const ciphertext = this.encryptGivenKeyInfo(key.olmKey, key.index);
        const { ciphertext: cipher, iv } = await encryptSymmetrically(
            this.pqSessionKey,
            key.pqKey,
            AUX,
        );
        const pqCiphertext = ciphertextToBase64(cipher, iv);

        return {
            ciphertext,
            pqCiphertext,
        };
    }

    encryptKeyCommitment(commitmentToKeys: string): string {
        const ciphertext = this.session.encrypt(
            new TextEncoder().encode(commitmentToKeys),
        );

        return ciphertext.ciphertext;
    }

    async encryptKeys(): Promise<{ ciphertext: string; pqCiphertext: string; }> {
        const ciphertext = this.encryptGivenKeyInfo(
            this.keyToSend.olmKey,
            this.keyToSend.index,
        );
        const { ciphertext: cipher, iv } = await encryptSymmetrically(
            this.pqSessionKey,
            this.keyToSend.pqKey,
            AUX,
        );
        const pqCiphertext = ciphertextToBase64(cipher, iv);

        return { ciphertext, pqCiphertext };
    }

    async decryptKeys(
            pId: string,
            ciphertext: string,
            pqCiphertext: string,
    ): Promise<MediaKeys> {
        const result = this.session.decrypt(NORMAL_MESSAGE, ciphertext);
        const index = result[result.length - 1];
        const key = result.slice(0, -1);
        const { ciphertext: pqCipher, iv } = base64ToCiphertext(pqCiphertext);
        const pqKey = await decryptSymmetrically(
            this.pqSessionKey,
            pqCipher,
            iv,
            AUX,
        );
        const mediaKey = {
            index,
            olmKey: key,
            pqKey,
            userID: pId,
        };

        return mediaKey;
    }

    encryptGivenKeyInfo(key: Uint8Array, index: number): string {
        const message = new Uint8Array(key.length + 1);

        message.set(key, 0);
        message.set([ index ], key.length);
        const encrypted = this.session.encrypt(message);

        return encrypted.ciphertext;
    }

    async deriveSharedPQkey(key1: Uint8Array, key2?: Uint8Array) {
        const secret = key2 || this.kemSecret;
        const key = deriveSymmetricCryptoKeyFromTwoKeys(
            key1,
            secret,
        );

        this.pqSessionKey = await importSymmetricCryptoKey(key);
    }
}
