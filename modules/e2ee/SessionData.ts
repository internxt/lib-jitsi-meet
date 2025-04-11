import { Session } from "vodozemac-wasm";

import { PROTOCOL_STATUS, ProtocolStatus, NORMAL_MESSAGE } from "./Types";

import { encryptKeyInfoPQ, decryptKeyInfoPQ } from "./crypto-utils";
import { deriveEncryptionKey, commitToMediaKeyShares } from "./crypto-workers";

export class SessionData {
    status: ProtocolStatus;
    commitment: string;
    private keyToSendOlm: Uint8Array;
    private keyToSendPQ: Uint8Array;
    private indexToSend: number;
    session: Session;
    private pqSessionKey: CryptoKey;
    kemSecret: Uint8Array;

    constructor(olmKey: Uint8Array, pqKey: Uint8Array, index: number) {
        this.status = PROTOCOL_STATUS.READY_TO_START;
        this.session = null as any;
        this.pqSessionKey = null as any;
        this.keyToSendOlm = olmKey;
        this.keyToSendPQ = pqKey;
        this.indexToSend = index;
    }
    indexChanged(index: number): boolean {
        return this.indexToSend !== index;
    }

    isDone(): boolean {
        return (
            this.status === PROTOCOL_STATUS.DONE ||
            this.status === PROTOCOL_STATUS.WAITING_DONE
        );
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
        this.keyToSendOlm = new Uint8Array();
        this.keyToSendPQ = new Uint8Array();
        this.indexToSend = -1;
    }

    async keyCommitment(id: string): Promise<string> {
        return commitToMediaKeyShares(
            id,
            this.keyToSendOlm,
            this.keyToSendPQ,
            this.indexToSend,
        );
    }

    encryptKeyInfo() {
        return this.encryptGivenKeyInfo(this.keyToSendOlm, this.indexToSend);
    }

    encryptGivenKeyInfo(key: Uint8Array, index: number): string {
        const message = new Uint8Array(key.length + 1);
        message.set(key, 0);
        message.set([index], key.length);
        const encrypted = this.session.encrypt(message);
        return encrypted.ciphertext;
    }

    decryptKeyInfo(ciphertext: string): { key: Uint8Array; index: number } {
        const result = this.session.decrypt(NORMAL_MESSAGE, ciphertext);
        const index = result[result.length - 1];
        const key = result.slice(0, -1);
        return { key, index };
    }

    async deriveSharedPQkey(key1: Uint8Array, key2: Uint8Array) {
        this.pqSessionKey = await deriveEncryptionKey(key1, key2);
    }

    async encryptCurrentPQkey() {
        return this.encryptPQkey(this.keyToSendPQ);
    }

    async encryptPQkey(pqKey: Uint8Array) {
        return encryptKeyInfoPQ(this.pqSessionKey, pqKey);
    }

    async decryptPQKey(pqCiphertext: string) {
        return decryptKeyInfoPQ(pqCiphertext, this.pqSessionKey);
    }
}
