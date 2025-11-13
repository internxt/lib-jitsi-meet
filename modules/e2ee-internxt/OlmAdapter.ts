import initVodozemac, { Account } from 'vodozemac-wasm';

import { genSymmetricKey, ratchetMediaKey } from './CryptoUtils';
import { SessionData } from './SessionData';
import {
    KeyInfo,
    MediaKeys,
    PQsessionAck,
    PQsessionInit,
    PROTOCOL_STATUS,
    SessionInit,
} from './Types';
import { base64ToUint8Array, decapsulateKyber, encapsulateKyber, generateKyberKeys, uint8ArrayToBase64 } from './Utils';


function getError(method: string, error: Error): Error {
    console.error(`E2E: ${error}`);

    return new Error(`E2E: Function ${method} failed: ${error}`);
}

export class OlmAdapter {
    private _mediaKey: MediaKeys;

    private _publicKyberKey: string = '';
    private _privateKyberKey: Uint8Array = new Uint8Array();
    private _olmAccount: Account;
    private _publicCurve25519Key: string = '';
    private readonly _olmDataMap: Map<string, SessionData>;

    constructor(id: string) {
        this._mediaKey = {
            index: -1,
            olmKey: new Uint8Array(),
            pqKey: new Uint8Array(),
            userID: id,
        };
        this._olmDataMap = new Map<string, SessionData>();
    }

    private _getParticipantOlmData(pId: string): SessionData {
        if (!this._olmDataMap.has(pId)) {
            this._olmDataMap.set(pId, new SessionData(this._mediaKey));
        }

        return this._olmDataMap.get(pId);
    }

    async init() {
        await initVodozemac();
    }

    genMyPublicKeys(): { pk: string; pkKyber: string; } {
        try {
            this._olmAccount = new Account();
            this._publicCurve25519Key = this._olmAccount.curve25519_key;

            const { publicKey, secretKey } = generateKyberKeys();
            const publicKeyBase64 = uint8ArrayToBase64(publicKey);

            this._publicKyberKey = publicKeyBase64;
            this._privateKyberKey = secretKey;

            return { pk: this._publicCurve25519Key, pkKyber: publicKeyBase64 };
        } catch (error) {
            throw getError('genMyPublicKeys', error);
        }
    }

    generateOneTimeKeys(size: number): string[] {
        try {
            this._olmAccount.generate_one_time_keys(size);
            const keys: string[] = Array.from(
                this._olmAccount.one_time_keys.values(),
            );

            return keys;
        } catch (error) {
            throw getError('generateOneTimeKeys', error);
        }
    }

    ratchetMyKeys(): MediaKeys {
        try {
            const key = ratchetMediaKey(this._mediaKey);

            this._mediaKey = key;

            return key;
        } catch (error) {
            throw getError('ratchetMyKeys', error);
        }
    }

    isSessionDone(pId: string): boolean {
        try {
            const olmData = this._getParticipantOlmData(pId);

            return olmData.isDone();
        } catch (error) {
            throw getError('isSessionDone', error);
        }
    }

    updateMyKeys(): MediaKeys {
        try {
            const newMediaKey = {
                index: this._mediaKey.index + 1,
                olmKey: genSymmetricKey(),
                pqKey: genSymmetricKey(),
                userID: this._mediaKey.userID,
            };

            this._mediaKey = newMediaKey;

            return newMediaKey;
        } catch (error) {
            throw getError('updateMyKeys', error);
        }
    }

    async encryptCurrentKey(pId: string): Promise<KeyInfo> {
        try {
            const olmData = this._getParticipantOlmData(pId);

            olmData.validateStatus(PROTOCOL_STATUS.DONE);
            const data = await olmData.createKeyInfoMessage(this._mediaKey);

            return data;
        } catch (error) {
            throw getError('encryptCurrentKey', error);
        }
    }

    deleteParticipantSession(pId: string) {
        this._olmDataMap.delete(pId);
    }

    clearParticipantSession(pId: string) {
        try {
            const olmData = this._getParticipantOlmData(pId);

            olmData.clearSession();
        } catch (error) {
            throw getError('clearParticipantSession', error);
        }
    }

    async clearMySession() {
        this._olmAccount?.free();
    }

    async createPQsessionInitMessage(
            pId: string,
            otKey: string,
            publicKey: string,
            publicKyberKey: string,
            commitment: string,
    ): Promise<PQsessionInit> {
        try {
            const olmData = this._getParticipantOlmData(pId);

            olmData.validateStatus(PROTOCOL_STATUS.READY_TO_START);

            olmData.createOutboundOLMchannel(
                this._olmAccount,
                publicKey,
                otKey,
                commitment,
            );

            const publicKeyArray = base64ToUint8Array(publicKyberKey);
            const { cipherText, sharedSecret } = encapsulateKyber(publicKeyArray);

            olmData.setSecret(sharedSecret);
            const commitmentToKeys = await olmData.keyCommitment();
            const ciphertext = olmData.encryptKeyCommitment(commitmentToKeys);

            olmData.setStatus(PROTOCOL_STATUS.WAITING_PQ_SESSION_ACK);

            return {
                ciphertext: ciphertext,
                encapsKyber: uint8ArrayToBase64(cipherText),
                publicKey: this._publicCurve25519Key,
                publicKyberKey: this._publicKyberKey,
            };
        } catch (error) {
            throw getError('createPQsessionInitMessage', error);
        }
    }

    async createPQsessionAckMessage(
            pId: string,
            encapsKyber: string,
            publicKey: string,
            publicKyberKey: string,
            ciphertext: string,
    ): Promise<PQsessionAck> {
        try {
            const olmData = this._getParticipantOlmData(pId);

            olmData.validateStatus(PROTOCOL_STATUS.WAITING_PQ_SESSION_INIT);

            olmData.createInboundOLMchannel(
                this._olmAccount,
                publicKey,
                ciphertext,
            );

            const decapsArray = base64ToUint8Array(encapsKyber);
            const decapsulatedSecret = decapsulateKyber(
                decapsArray,
                this._privateKyberKey,
            );

            const publicKeyArray = base64ToUint8Array(publicKyberKey);
            const { cipherText, sharedSecret }
                = encapsulateKyber(publicKeyArray);
            const encapsulatedBase64 = uint8ArrayToBase64(cipherText);

            await olmData.deriveSharedPQkey(sharedSecret, decapsulatedSecret);

            const { ciphertext: olmEncKeyInfo, pqCiphertext: pqEncKeyInfo }
                = await olmData.encryptKeys();

            olmData.setStatus(PROTOCOL_STATUS.WAITING_SESSION_ACK);

            return {
                ciphertext: olmEncKeyInfo,
                encapsKyber: encapsulatedBase64,
                pqCiphertext: pqEncKeyInfo,
            };
        } catch (error) {
            throw getError('createPQsessionAckMessage', error);
        }
    }

    async createSessionAckMessage(
            pId: string,
            encapsKyber: string,
            ciphertext: string,
            pqCiphertext: string,
    ): Promise<{
                data: KeyInfo;
                key: MediaKeys;
            }> {
        try {
            const olmData = this._getParticipantOlmData(pId);

            olmData.validateStatus(PROTOCOL_STATUS.WAITING_PQ_SESSION_ACK);

            const decapsArray = base64ToUint8Array(encapsKyber);
            const decapsulatedSecret = decapsulateKyber(
                decapsArray,
                this._privateKyberKey,
            );

            await olmData.deriveSharedPQkey(decapsulatedSecret);
            const key = await olmData.decryptKeys(
                pId,
                ciphertext,
                pqCiphertext,
            );

            await olmData.validateCommitment(key);

            const {
                ciphertext: olmCiphertext,
                pqCiphertext: pqCiphertextBase64,
            } = await olmData.encryptKeys();

            const data: KeyInfo = {
                ciphertext: olmCiphertext,
                pqCiphertext: pqCiphertextBase64,
            };

            olmData.setStatus(PROTOCOL_STATUS.WAITING_DONE);

            return { data, key };
        } catch (error) {
            throw getError('createSessionAckMessage', error);
        }
    }

    async createSessionDoneMessage(
            pId: string,
            ciphertext: string,
            pqCiphertext: string,
    ): Promise<{
                key: MediaKeys;
                keyChanged: boolean;
            }> {
        try {
            const olmData = this._getParticipantOlmData(pId);

            olmData.validateStatus(PROTOCOL_STATUS.WAITING_SESSION_ACK);

            const key = await olmData.decryptKeys(
                pId,
                ciphertext,
                pqCiphertext,
            );

            await olmData.validateCommitment(key);

            const keyChanged = olmData.indexChanged(this._mediaKey);

            olmData.setDone();

            return { key, keyChanged };
        } catch (error) {
            throw getError('createSessionDoneMessage', error);
        }
    }

    processSessionDoneMessage(pId: string): boolean {
        try {
            const olmData = this._getParticipantOlmData(pId);

            olmData.validateStatus(PROTOCOL_STATUS.WAITING_DONE);
            const keyChanged = olmData.indexChanged(this._mediaKey);

            olmData.setDone();

            return keyChanged;
        } catch (error) {
            throw getError('processSessionDoneMessage', error);
        }
    }

    async decryptKey(
            pId: string,
            ciphertext: string,
            pqCiphertext: string,
    ): Promise<MediaKeys> {
        try {
            const olmData = this._getParticipantOlmData(pId);

            if (!olmData.isDone()) {
                throw new Error('Session init is not done yet');
            }

            return olmData.decryptKeys(pId, ciphertext, pqCiphertext);
        } catch (error) {
            throw getError('decryptKey', error);
        }
    }

    async createSessionInitMessage(
            pId: string,
            otKey: string,
    ): Promise<SessionInit> {
        try {
            const olmData = this._getParticipantOlmData(pId);

            olmData.validateStatus(PROTOCOL_STATUS.READY_TO_START);
            const commitment = await olmData.keyCommitment();

            olmData.setStatus(PROTOCOL_STATUS.WAITING_PQ_SESSION_INIT);

            return {
                commitment,
                otKey,
                publicKey: this._publicCurve25519Key,
                publicKyberKey: this._publicKyberKey,
            };
        } catch (error) {
            throw getError('createSessionInitMessage', error);
        }
    }
}
