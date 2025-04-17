import { Session, Account } from "vodozemac-wasm";

import {
    PROTOCOL_STATUS,
    ProtocolStatus,
    NORMAL_MESSAGE,
    KeyInfo,
    MediaKey,
    PREKEY_MESSAGE,
} from "./Types";

import {
    encryptKeyInfoPQ,
    decryptKeyInfoPQ,
    encapsulateSecret,
} from "./crypto-utils";
import { deriveEncryptionKey, commitToMediaKeyShares } from "./crypto-workers";

export class SessionData {
    private status: ProtocolStatus;
    private commitment: string;
    private keyToSend: MediaKey;
    private session: Session;
    private pqSessionKey: CryptoKey;
    private kemSecret: Uint8Array;

    constructor(key: MediaKey) {
        this.status = PROTOCOL_STATUS.READY_TO_START;
        this.session = null as any;
        this.pqSessionKey = null as any;
        this.keyToSend = key;
    }
    indexChanged(key: MediaKey): boolean {
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

    async encapsulate(publicKyberKey: string): Promise<string> {
        const { encapsulatedBase64, sharedSecret } =
            await encapsulateSecret(publicKyberKey);
        this.kemSecret = sharedSecret;
        return encapsulatedBase64;
    }

    isDone(): boolean {
        return (
            this.status === PROTOCOL_STATUS.DONE ||
            this.status === PROTOCOL_STATUS.WAITING_DONE
        );
    }

    validateStatus(status: ProtocolStatus) {
        if (this.status !== status)
            throw new Error(
                `Protocol status is ${this.status} but expected ${status}.`,
            );
    }
    async validateCommitment(id: string, key: MediaKey) {
        const commitment = await commitToMediaKeyShares(id, key);
        if (this.commitment !== commitment)
            throw new Error(`Keys do not match the commitment.`);
    }

    setStatus(status: ProtocolStatus) {
        this.status = status;
    }

    clearSession() {
        if (this.session) {
            this.session.free();
            this.session = undefined;
        }
        this.status = PROTOCOL_STATUS.TERMINATED;
    }

    setDone() {
        this.status = PROTOCOL_STATUS.DONE;
        this.commitment = "";
        this.kemSecret = new Uint8Array();
        this.keyToSend = {
            olmKey: new Uint8Array(),
            pqKey: new Uint8Array(),
            index: -1,
        };
    }

    async keyCommitment(id: string): Promise<string> {
        return commitToMediaKeyShares(id, this.keyToSend);
    }

    async createKeyInfoMessage(key: MediaKey): Promise<KeyInfo> {
        const ciphertext = this.encryptGivenKeyInfo(key.olmKey, key.index);
        const pqCiphertext = await encryptKeyInfoPQ(
            this.pqSessionKey,
            key.pqKey,
        );
        const data: KeyInfo = {
            ciphertext,
            pqCiphertext,
        };
        return data;
    }

    encryptKeyCommitment(commitmentToKeys: string): string {
        const ciphertext = this.session.encrypt(
            new TextEncoder().encode(commitmentToKeys),
        );
        return ciphertext.ciphertext;
    }

    async encryptKeys(): Promise<{ ciphertext: string; pqCiphertext: string }> {
        const ciphertext = this.encryptGivenKeyInfo(
            this.keyToSend.olmKey,
            this.keyToSend.index,
        );
        const pqCiphertext = await encryptKeyInfoPQ(
            this.pqSessionKey,
            this.keyToSend.pqKey,
        );
        return { ciphertext, pqCiphertext };
    }

    async decryptKeys(
        ciphertext: string,
        pqCiphertext: string,
    ): Promise<MediaKey> {
        const result = this.session.decrypt(NORMAL_MESSAGE, ciphertext);
        const index = result[result.length - 1];
        const key = result.slice(0, -1);
        const pqKey = await decryptKeyInfoPQ(pqCiphertext, this.pqSessionKey);
        const mediaKey = {
            olmKey: key,
            pqKey,
            index,
        };
        return mediaKey;
    }

    encryptGivenKeyInfo(key: Uint8Array, index: number): string {
        const message = new Uint8Array(key.length + 1);
        message.set(key, 0);
        message.set([index], key.length);
        const encrypted = this.session.encrypt(message);
        return encrypted.ciphertext;
    }

    async deriveSharedPQkey(key1: Uint8Array, key2?: Uint8Array) {
        const secret = key2 || this.kemSecret;
        this.pqSessionKey = await deriveEncryptionKey(key1, secret);
    }
}
