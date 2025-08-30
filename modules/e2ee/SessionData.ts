import { Session, Account } from "vodozemac-wasm";

import {
    PROTOCOL_STATUS,
    ProtocolStatus,
    NORMAL_MESSAGE,
    KeyInfo,
    PREKEY_MESSAGE,
} from "./Types";

import { MediaKeys, symmetric, hash, deriveKey, utils, pq } from "internxt-crypto";
const AUX = 'KeyInfoPQ';

export class SessionData {
    private status: ProtocolStatus;
    private commitment: string;
    private keyToSend: MediaKeys;
    private session: Session;
    private pqSessionKey: CryptoKey;
    private kemSecret: Uint8Array;

    constructor(key: MediaKeys) {
        this.status = PROTOCOL_STATUS.READY_TO_START;
        this.session = null as any;
        this.pqSessionKey = null as any;
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
        const publicKey = utils.base64ToUint8Array(publicKyberKey);
        const { cipherText, sharedSecret } =
            pq.encapsulateKyber(publicKey);
        this.kemSecret = sharedSecret;
        return utils.uint8ArrayToBase64(cipherText);
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
    async validateCommitment(key: MediaKeys) {
        const commitment = await hash.comitToMediaKey(key);
        if (this.commitment !== commitment)
            throw new Error(`Keys do not match the commitment.`);
    }

    setStatus(status: ProtocolStatus) {
        if(this.status=== PROTOCOL_STATUS.TERMINATED)  throw new Error(`Terminated while processing.`);
        else this.status = status;
    }

    clearSession() {
        this.status = PROTOCOL_STATUS.TERMINATED;
        if (this.session) {
            this.session.free();
        }
    }

    setDone() {
        this.status = PROTOCOL_STATUS.DONE;
        this.commitment = "";
        this.kemSecret = new Uint8Array();
        this.keyToSend = {
            olmKey: new Uint8Array(),
            pqKey: new Uint8Array(),
            index: -1,
            userID: '',
        };
    }

    async keyCommitment(): Promise<string> {
        return hash.comitToMediaKey(this.keyToSend);
    }

    async createKeyInfoMessage(key: MediaKeys): Promise<KeyInfo> {
        const ciphertext = this.encryptGivenKeyInfo(key.olmKey, key.index);
        const result = await symmetric.encryptSymmetrically(this.pqSessionKey, key.pqKey, AUX);
        const pqCiphertext = utils.ciphertextToBase64(result);
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

    async encryptKeys(): Promise<{ ciphertext: string; pqCiphertext: string }> {
        const ciphertext = this.encryptGivenKeyInfo(
            this.keyToSend.olmKey,
            this.keyToSend.index,
        );
        const result = await symmetric.encryptSymmetrically(this.pqSessionKey,  this.keyToSend.pqKey, AUX);
        const pqCiphertext = utils.ciphertextToBase64(result);
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
        const pqCipher = utils.base64ToCiphertext(pqCiphertext);
        const pqKey = await symmetric.decryptSymmetrically(this.pqSessionKey, pqCipher, AUX);
        const mediaKey = {
            olmKey: key,
            pqKey,
            index,
            userID: pId
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
        this.pqSessionKey = await deriveKey.deriveSymmetricCryptoKeyFromTwoKeys(key1, secret);
    }
}
