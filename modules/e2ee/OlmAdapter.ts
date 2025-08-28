import initVodozemac, { Account } from "vodozemac-wasm";
import {
    generateKyberKeys,
    getError,
} from "./crypto-utils";
import { ratchetKey, commitToIdentityKeys } from "./crypto-workers";
import {
    PROTOCOL_STATUS,
    KeyInfo,
    PQsessionAck,
    SessionAck,
    PQsessionInit,
    SessionInit,
} from "./Types";

import { SessionData } from "./SessionData";
import { MediaKeys, symmetric, utils, pq } from "internxt-crypto";

export class OlmAdapter {
    private readonly _myId: string;
    private _mediaKey: MediaKeys;

    private _publicKyberKeyBase64: string;
    private _privateKyberKey: Uint8Array;
    private _olmAccount: Account;
    private _publicCurve25519Key: string;
    private _indenityKeyCommitment: string;
    private readonly _olmDataMap: Map<string, SessionData>;

    constructor(id: string) {
        this._myId = id;
        this._mediaKey = {
            olmKey: new Uint8Array(),
            pqKey: new Uint8Array(),
            index: -1,
            userID: id,
        };
        this._publicKyberKeyBase64 = "";
        this._privateKyberKey = new Uint8Array();
        this._publicCurve25519Key = "";
        this._indenityKeyCommitment = "";
        this._olmDataMap = new Map<string, SessionData>();
    }

    async init() {
        try {
            await initVodozemac();

            this._olmAccount = new Account();
            this._publicCurve25519Key = this._olmAccount.curve25519_key;

            const { publicKeyBase64, privateKey } = await generateKyberKeys();
            this._publicKyberKeyBase64 = publicKeyBase64;
            this._privateKyberKey = privateKey;
            this._indenityKeyCommitment = await commitToIdentityKeys(
                this._myId,
                this._publicKyberKeyBase64,
                this._publicCurve25519Key,
            );
        } catch (error) {
            throw getError("ínit", error);
        }
    }

    getMyIdentityKeysCommitment(): string {
        return this._indenityKeyCommitment;
    }

    generateOneTimeKeys(size: number): string[] {
        try {
            this._olmAccount.generate_one_time_keys(size);
            const keys: string[] = Array.from(
                this._olmAccount.one_time_keys.values(),
            );
            return keys;
        } catch (error) {
            throw getError("generateOneTimeKeys", error);
        }
    }

    async ratchetMyKeys(): Promise<MediaKeys> {
        try {
            const newMediaKey = {
                olmKey: await ratchetKey(this._mediaKey.olmKey),
                pqKey: await ratchetKey(this._mediaKey.pqKey),
                index: this._mediaKey.index + 1,
                userID: this._mediaKey.userID,
            };
            this._mediaKey = newMediaKey;
            return newMediaKey;
        } catch (error) {
            throw getError("ratchetMyKeys", error);
        }
    }

    checkIfShouldRatchetParticipantKey(pId: string): boolean {
        try {
            const olmData = this._getParticipantOlmData(pId);
            return olmData.isDone();
        } catch (error) {
            throw getError("checkIfShouldRatchetParticipantKey", error);
        }
    }

    updateMyKeys(): MediaKeys {
        try {
            const newMediaKey = {
                olmKey: symmetric.genSymmetricKey(),
                pqKey: symmetric.genSymmetricKey(),
                index: this._mediaKey.index + 1,
                userID: this._mediaKey.userID,
            };
            this._mediaKey = newMediaKey;
            return newMediaKey;
        } catch (error) {
            throw getError("updateMyKeys", error);
        }
    }

    async checkIfShouldSendKeyInfoToParticipant(
        pId: string,
    ): Promise<KeyInfo | undefined> {
        try {
            const olmData = this._getParticipantOlmData(pId);
            let data = undefined;

            if (olmData.isDone()) {
                data = await olmData.createKeyInfoMessage(this._mediaKey);
            }
            return data;
        } catch (error) {
            throw getError("checkIfShouldSendKeyInfoToParticipant", error);
        }
    }

    clearParticipantSession(pId: string) {
        try {
            const olmData = this._getParticipantOlmData(pId);
            olmData.clearSession();
            this._olmDataMap.delete(pId);
        } catch (error) {
            throw getError("clearParticipantSession", error);
        }
    }

    private _getParticipantOlmData(pId: string): SessionData {
        let result = this._olmDataMap.get(pId);
        if (!result) {
            result = new SessionData(this._mediaKey);
            this._olmDataMap.set(pId, result);
        }
        return result;
    }

    async clearMySession() {
        if (this._olmAccount) {
            this._olmAccount.free();
            this._olmAccount = undefined;
        }
    }

    async createPQsessionInitMessage(
        pId: string,
        otKey: string,
        publicKey: string,
        publicKyberKey: string,
        commitment: string,
    ): Promise<{ data: PQsessionInit; keyCommitment: string }> {
        try {
            const olmData = this._getParticipantOlmData(pId);
            olmData.validateStatus(PROTOCOL_STATUS.READY_TO_START);

            const keyCommitment = await commitToIdentityKeys(
                pId,
                publicKyberKey,
                publicKey,
            );

            olmData.createOutboundOLMchannel(
                this._olmAccount,
                publicKey,
                otKey,
                commitment,
            );

            const encapsulatedBase64 =
                 olmData.encapsulate(publicKyberKey);
            const commitmentToKeys = await olmData.keyCommitment(this._myId);

            const ciphertext = olmData.encryptKeyCommitment(commitmentToKeys);

            const data: PQsessionInit = {
                encapsKyber: encapsulatedBase64,
                publicKey: this._publicCurve25519Key,
                publicKyberKey: this._publicKyberKeyBase64,
                ciphertext: ciphertext,
            };

            olmData.setStatus(PROTOCOL_STATUS.WAITING_PQ_SESSION_ACK);
            return { data, keyCommitment };
        } catch (error) {
            throw getError("createPQsessionInitMessage", error);
        }
    }

    async createPQsessionAckMessage(
        pId: string,
        encapsKyber: string,
        publicKey: string,
        publicKyberKey: string,
        ciphertext: string,
    ): Promise<{ data: PQsessionAck; keyCommitment: string }> {
        try {
            const olmData = this._getParticipantOlmData(pId);
            olmData.validateStatus(PROTOCOL_STATUS.WAITING_PQ_SESSION_INIT);

            const keyCommitment = await commitToIdentityKeys(
                pId,
                publicKyberKey,
                publicKey,
            );

            olmData.createInboundOLMchannel(
                this._olmAccount,
                publicKey,
                ciphertext,
            );

            const decapsArray = utils.base64ToUint8Array(encapsKyber);
             const decapsulatedSecret = pq.kyber512.decapsulateKyber(
            decapsArray,
            this._privateKyberKey,
        );

             const publicKeyArray = utils.base64ToUint8Array(publicKyberKey);
        const { cipherText, sharedSecret } =
            pq.kyber512.encapsulateKyber(publicKeyArray);
        const encapsulatedBase64 = utils.uint8ArrayToBase64(cipherText);

            await olmData.deriveSharedPQkey(sharedSecret, decapsulatedSecret);

            const { ciphertext: olmEncKeyInfo, pqCiphertext: pqEncKeyInfo } =
                await olmData.encryptKeys();

            const data: PQsessionAck = {
                encapsKyber: encapsulatedBase64,
                ciphertext: olmEncKeyInfo,
                pqCiphertext: pqEncKeyInfo,
            };

            olmData.setStatus(PROTOCOL_STATUS.WAITING_SESSION_ACK);
            return { data, keyCommitment };
        } catch (error) {
            throw getError("createPQsessionAckMessage", error);
        }
    }

    async createSessionAckMessage(
        pId: string,
        encapsKyber: string,
        ciphertext: string,
        pqCiphertext: string,
    ): Promise<{
        data: SessionAck;
        key: MediaKeys;
    }> {
        try {
            const olmData = this._getParticipantOlmData(pId);
            olmData.validateStatus(PROTOCOL_STATUS.WAITING_PQ_SESSION_ACK);

             const decapsArray = utils.base64ToUint8Array(encapsKyber);
             const decapsulatedSecret = pq.kyber512.decapsulateKyber(
            decapsArray,
            this._privateKyberKey,
        );

            await olmData.deriveSharedPQkey(decapsulatedSecret);
            const key = await olmData.decryptKeys(pId, ciphertext, pqCiphertext);
            await olmData.validateCommitment(key);

            const {
                ciphertext: olmCiphertext,
                pqCiphertext: pqCiphertextBase64,
            } = await olmData.encryptKeys();

            const data: SessionAck = {
                ciphertext: olmCiphertext,
                pqCiphertext: pqCiphertextBase64,
            };

            olmData.setStatus(PROTOCOL_STATUS.WAITING_DONE);
            return { data, key };
        } catch (error) {
            throw getError("createSessionAckMessage", error);
        }
    }

    async createSessionDoneMessage(
        pId: string,
        ciphertext: string,
        pqCiphertext: string,
    ): Promise<{
        data: KeyInfo | undefined;
        key: MediaKeys;
    }> {
        try {
            const olmData = this._getParticipantOlmData(pId);
            olmData.validateStatus(PROTOCOL_STATUS.WAITING_SESSION_ACK);

            const key = await olmData.decryptKeys(pId, ciphertext, pqCiphertext);
            await olmData.validateCommitment(key);

            let data = undefined;
            if (olmData.indexChanged(this._mediaKey)) {
                data = await olmData.createKeyInfoMessage(this._mediaKey);
            }
            olmData.setDone();

            return { data, key };
        } catch (error) {
            throw getError("createSessionDoneMessage", error);
        }
    }

    async processSessionDoneMessage(pId: string): Promise<KeyInfo | undefined> {
        try {
            const olmData = this._getParticipantOlmData(pId);
            olmData.validateStatus(PROTOCOL_STATUS.WAITING_DONE);

            let data = undefined;
            if (olmData.indexChanged(this._mediaKey)) {
                data = await olmData.createKeyInfoMessage(this._mediaKey);
            }
            olmData.setDone();

            return data;
        } catch (error) {
            throw getError("processSessionDoneMessage", error);
        }
    }

    async processKeyInfoMessage(
        pId: string,
        ciphertext: string,
        pqCiphertext: string,
    ): Promise<MediaKeys> {
        try {
            const olmData = this._getParticipantOlmData(pId);

            if (!olmData.isDone()) {
                throw new Error(`Session init is not done yet`);
            }

            return olmData.decryptKeys(pId, ciphertext, pqCiphertext);
        } catch (error) {
            throw getError("processKeyInfoMessage", error);
        }
    }

    async createSessionInitMessage(
        pId: string,
        otKey: string,
    ): Promise<SessionInit> {
        try {
            const olmData = this._getParticipantOlmData(pId);
            olmData.validateStatus(PROTOCOL_STATUS.READY_TO_START);

            const commitment = await olmData.keyCommitment(this._myId);
            const data: SessionInit = {
                otKey,
                publicKey: this._publicCurve25519Key,
                publicKyberKey: this._publicKyberKeyBase64,
                commitment,
            };
            olmData.setStatus(PROTOCOL_STATUS.WAITING_PQ_SESSION_INIT);

            return data;
        } catch (error) {
            throw getError("createSessionInitMessage", error);
        }
    }
}
