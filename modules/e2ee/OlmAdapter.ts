import initVodozemac, { Account } from "vodozemac-wasm";
import {
    generateKyberKeys,
    encapsulateSecret,
    decapsulateSecret,
    generateKey,
} from "./crypto-utils";
import {
    ratchetKey,
    commitToIdentityKeys,
    commitToMediaKeyShares,
} from "./crypto-workers";
import {
    PROTOCOL_STATUS,
    KeyInfo,
    PQsessionAck,
    SessionAck,
    PQsessionInit,
    SessionInit,
    PREKEY_MESSAGE,
} from "./Types";

import { SessionData } from "./SessionData";

export class OlmAdapter {
    private readonly _myId: string;
    private _olmInitialized: boolean;
    private _mediaKeyOlm: Uint8Array;
    private _mediaKeyPQ: Uint8Array;
    private _mediaKeyIndex: number;

    private _publicKyberKeyBase64: string;
    private _privateKyberKey: Uint8Array;
    private _olmAccount: Account;
    private _publicCurve25519Key: string;
    private _indenityKeyCommitment: string;
    private readonly _olmDataMap: Map<string, SessionData>;

    constructor(id: string) {
        this._myId = id;
        this._mediaKeyOlm = new Uint8Array();
        this._mediaKeyPQ = new Uint8Array();
        this._mediaKeyIndex = -1;
        this._publicKyberKeyBase64 = "";
        this._privateKyberKey = new Uint8Array();
        this._publicCurve25519Key = "";
        this._indenityKeyCommitment = "";
        this._olmDataMap = new Map<string, SessionData>();

        this._olmInitialized = false;
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
            this._olmInitialized = true;
        } catch (error) {
            throw new Error(`E2E:  Failed to initialize Olm: ${error}`);
        }
    }

    async createKeyInfoMessage(
        pId: string,
        olmData: SessionData,
    ): Promise<KeyInfo> {
        try {
            const pqCiphertext = await olmData.encryptPQkey(this._mediaKeyPQ);
            const ciphertext = olmData.encryptGivenKeyInfo(
                this._mediaKeyOlm,
                this._mediaKeyIndex,
            );

            const data: KeyInfo = {
                ciphertext,
                pqCiphertext,
            };
            console.info(`E2E: Sending KEY_INFO to the participant ${pId}`);

            return data;
        } catch (error) {
            throw new Error(`E2E: createKeyInfoMessage failed: ${error}`);
        }
    }

    isInitialized(): boolean {
        return this._olmInitialized;
    }

    getMyIdentityKeysCommitment(): string {
        return this._indenityKeyCommitment;
    }

    generateOneTimeKeys(size: number): string[] {
        try {
            console.info(
                `E2E: About to generate ${size} one-time keys, init done = ${this.isInitialized()}`,
            );
            this._olmAccount.generate_one_time_keys(size);
            const keys: string[] = Array.from(
                this._olmAccount.one_time_keys.values(),
            );
            return keys;
        } catch (error) {
            throw new Error(`E2E: Failed to generate one time keys: ${error}`);
        }
    }

    async ratchetMyKeys(): Promise<{
        olmKey: Uint8Array;
        pqKey: Uint8Array;
        index: number;
    }> {
        try {
            this._mediaKeyOlm = await ratchetKey(this._mediaKeyOlm);
            this._mediaKeyPQ = await ratchetKey(this._mediaKeyPQ);
            this._mediaKeyIndex++;
            return {
                olmKey: this._mediaKeyOlm,
                pqKey: this._mediaKeyPQ,
                index: this._mediaKeyIndex,
            };
        } catch (error) {
            throw new Error(`Failed to ratchet my keys: ${error}`);
        }
    }
    checkIfShouldRatchetParticipantKey(pId: string): boolean {
        try {
            const olmData = this._getParticipantOlmData(pId);
            return olmData.isDone();
        } catch (error) {
            throw new Error(
                `Checking if should ratchet keys for ${pId} failed: ${error}`,
            );
        }
    }

    updateMyKeys(): { olmKey: Uint8Array; pqKey: Uint8Array; index: number } {
        try {
            this._mediaKeyOlm = generateKey();
            this._mediaKeyPQ = generateKey();
            this._mediaKeyIndex++;
            return {
                olmKey: this._mediaKeyOlm,
                pqKey: this._mediaKeyPQ,
                index: this._mediaKeyIndex,
            };
        } catch (error) {
            throw new Error(`Updating my keys failed: ${error}`);
        }
    }

    async checkIfShouldSendKeyInfoToParticipant(
        pId: string,
    ): Promise<KeyInfo | undefined> {
        try {
            const olmData = this._getParticipantOlmData(pId);
            let data = undefined;

            if (olmData.isDone()) {
                data = await this.createKeyInfoMessage(pId, olmData);
            }
            return data;
        } catch (error) {
            throw new Error(`Check if should send key info failed: ${error}`);
        }
    }

    clearParticipantSession(pId: string) {
        try {
            const olmData = this._getParticipantOlmData(pId);
            olmData.clearSession();
        } catch (error) {
            console.error(
                `E2E: Failed to clear session for participat ${pId}: ${error}`,
            );
        }
    }

    _getParticipantOlmData(pId: string): SessionData {
        let result = this._olmDataMap.get(pId);
        if (!result) {
            result = new SessionData(
                this._mediaKeyOlm,
                this._mediaKeyPQ,
                this._mediaKeyIndex,
            );
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

            if (olmData.status !== PROTOCOL_STATUS.READY_TO_START) {
                throw new Error(`Protocol status is ${olmData.status}`);
            }

            olmData.commitment = commitment;
            const keyCommitment = await commitToIdentityKeys(
                pId,
                publicKyberKey,
                publicKey,
            );
            olmData.session = this._olmAccount.create_outbound_session(
                publicKey,
                otKey,
            );

            const { encapsulatedBase64, sharedSecret } =
                await encapsulateSecret(publicKyberKey);
            olmData.kemSecret = sharedSecret;

            const commitmentToKeys = await olmData.keyCommitment(this._myId);

            const ciphertext = olmData.session.encrypt(
                new TextEncoder().encode(commitmentToKeys),
            );

            const data: PQsessionInit = {
                encapsKyber: encapsulatedBase64,
                publicKey: this._publicCurve25519Key,
                publicKyberKey: this._publicKyberKeyBase64,
                ciphertext: ciphertext.ciphertext,
            };

            olmData.status = PROTOCOL_STATUS.WAITING_PQ_SESSION_ACK;
            return { data, keyCommitment };
        } catch (error) {
            throw new Error(`E2E: replyToSessionInit failed: ${error}`);
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

            if (olmData.status !== PROTOCOL_STATUS.WAITING_PQ_SESSION_INIT) {
                throw new Error(`Protocol status is ${olmData.status}`);
            }
            const keyCommitment = await commitToIdentityKeys(
                pId,
                publicKyberKey,
                publicKey,
            );

            const { plaintext, session } =
                this._olmAccount.create_inbound_session(
                    publicKey,
                    PREKEY_MESSAGE,
                    ciphertext,
                );

            olmData.session = session;
            olmData.commitment = new TextDecoder().decode(plaintext);

            const decapsulatedSecret = await decapsulateSecret(
                encapsKyber,
                this._privateKyberKey,
            );

            const { encapsulatedBase64, sharedSecret } =
                await encapsulateSecret(publicKyberKey);

            await olmData.deriveSharedPQkey(decapsulatedSecret, sharedSecret);

            const pqEncKeyInfo = await olmData.encryptCurrentPQkey();

            const olmEncKeyInfo = olmData.encryptKeyInfo();

            const data: PQsessionAck = {
                encapsKyber: encapsulatedBase64,
                ciphertext: olmEncKeyInfo,
                pqCiphertext: pqEncKeyInfo,
            };

            olmData.status = PROTOCOL_STATUS.WAITING_SESSION_ACK;
            return { data, keyCommitment };
        } catch (error) {
            throw new Error(`E2E: replyToPQSessionInit failed: ${error}`);
        }
    }

    async createSessionAckMessage(
        pId: string,
        encapsKyber: string,
        ciphertext: string,
        pqCiphertext: string,
    ): Promise<{
        data: SessionAck;
        olmKey: Uint8Array;
        pqKey: Uint8Array;
        index: number;
    }> {
        try {
            const olmData = this._getParticipantOlmData(pId);

            if (olmData.status !== PROTOCOL_STATUS.WAITING_PQ_SESSION_ACK) {
                throw new Error(`Protocol status is ${olmData.status}`);
            }
            const decapsulatedSecret = await decapsulateSecret(
                encapsKyber,
                this._privateKyberKey,
            );

            await olmData.deriveSharedPQkey(
                olmData.kemSecret,
                decapsulatedSecret,
            );
            const { key, index } = olmData.decryptKeyInfo(ciphertext);
            const pqKey = await olmData.decryptPQKey(pqCiphertext);

            const commitment = await commitToMediaKeyShares(
                pId,
                key,
                pqKey,
                index,
            );

            if (olmData.commitment != commitment) {
                throw new Error(`Keys do not match the commitment.`);
            }
            console.info(`E2E: Recived new keys from ${pId}, index = ${index}`);

            const olmCiphertext = olmData.encryptKeyInfo();
            const pqCiphertextBase64 = await olmData.encryptCurrentPQkey();

            console.info(`E2E: Sent my keys to ${pId}`);

            const data: SessionAck = {
                ciphertext: olmCiphertext,
                pqCiphertext: pqCiphertextBase64,
            };

            olmData.status = PROTOCOL_STATUS.WAITING_DONE;
            return { data, olmKey: key, pqKey: pqKey, index: index };
        } catch (error) {
            throw new Error(`E2E: replyToPQSessionAck failed: ${error}`);
        }
    }

    async createSessionDoneMessage(
        pId: string,
        ciphertext: string,
        pqCiphertext: string,
    ): Promise<{
        data: KeyInfo | undefined;
        olmKey: Uint8Array;
        pqKey: Uint8Array;
        index: number;
    }> {
        try {
            const olmData = this._getParticipantOlmData(pId);

            if (olmData.status !== PROTOCOL_STATUS.WAITING_SESSION_ACK) {
                throw new Error(`Protocol status is ${olmData.status}`);
            }

            const { key, index } = olmData.decryptKeyInfo(ciphertext);
            const pqKey = await olmData.decryptPQKey(pqCiphertext);
            const commitment = await commitToMediaKeyShares(
                pId,
                key,
                pqKey,
                index,
            );

            if (olmData.commitment !== commitment) {
                throw new Error(`Keys do not match the commitment.`);
            }

            console.info(`E2E: Recived new keys from ${pId}, index = ${index}`);
            let data = undefined;
            if (olmData.indexChanged(this._mediaKeyIndex)) {
                console.info(
                    `E2E: Keys changes during session-init, sending new keys to ${pId}.`,
                );
                data = await this.createKeyInfoMessage(pId, olmData);
            }
            olmData.setDone();

            return { data, olmKey: key, pqKey: pqKey, index: index };
        } catch (error) {
            throw new Error(`createSessionDoneMessage failed: ${error}`);
        }
    }

    async processSessionDoneMessage(pId: string): Promise<KeyInfo | undefined> {
        try {
            const olmData = this._getParticipantOlmData(pId);

            if (olmData.status !== PROTOCOL_STATUS.WAITING_DONE) {
                throw new Error(`Protocol status is ${olmData.status}`);
            }

            let data = undefined;
            if (olmData.indexChanged(this._mediaKeyIndex)) {
                console.info(
                    `E2E: Keys changes during session-init, sending new keys to ${pId}.`,
                );
                data = await this.createKeyInfoMessage(pId, olmData);
            }
            olmData.setDone();
            console.info(
                `E2E: Participant ${pId} established E2E channel with us.`,
            );

            return data;
        } catch (error) {
            throw new Error(`E2E: replyToSessionAck failed: ${error}`);
        }
    }

    async processKeyInfoMessage(
        pId: string,
        ciphertext: string,
        pqCiphertext: string,
    ): Promise<{ olmKey: Uint8Array; pqKey: Uint8Array; index: number }> {
        try {
            const olmData = this._getParticipantOlmData(pId);

            if (!olmData.isDone()) {
                throw new Error(`Session init is not done yet`);
            }

            const { key, index } = olmData.decryptKeyInfo(ciphertext);
            const pqKey = await olmData.decryptPQKey(pqCiphertext);

            return { olmKey: key, pqKey: pqKey, index: index };
        } catch (error) {
            throw new Error(`E2E: processKeyInfoMessage failed: ${error}`);
        }
    }

    async createSessionInitMessage(
        pId: string,
        otKey: string,
    ): Promise<SessionInit> {
        try {
            const olmData = this._getParticipantOlmData(pId);
            if (olmData.status !== PROTOCOL_STATUS.READY_TO_START) {
                throw new Error(`Protocol status is ${olmData.status}`);
            }
            console.info(`E2E: Sending session-init to participant ${pId}`);

            const commitment = await olmData.keyCommitment(this._myId);

            const data: SessionInit = {
                otKey,
                publicKey: this._publicCurve25519Key,
                publicKyberKey: this._publicKyberKeyBase64,
                commitment,
            };

            olmData.status = PROTOCOL_STATUS.WAITING_PQ_SESSION_INIT;
            return data;
        } catch (error) {
            throw new Error(`E2E: createSessionInitMessage failed: ${error}`);
        }
    }
}
