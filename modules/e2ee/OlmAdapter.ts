import initVodozemac, {
    Account,
    Session,
    EncryptedOlmMessage,
} from "vodozemac-wasm";

import {
    generateKyberKeys,
    encapsulateSecret,
    decapsulateSecret,
    decryptKeyInfoPQ,
    encryptKeyInfoPQ,
    generateKey,
} from "./crypto-utils";
import {
    ratchetKey,
    commitToIdentityKeys,
    deriveEncryptionKey,
    commitToMediaKeyShares,
} from "./crypto-workers";
import JitsiParticipant from "../../JitsiParticipant";
import {
    PROTOCOL_STATUS,
    ProtocolStatus,
    KeyInfo,
    PQsessionAck,
    SessionAck,
    PQsessionInit,
    SessionInit,
} from "./Types";

export class OlmData {
    status: ProtocolStatus;
    commitment: string;
    keyToSendOlm: Uint8Array;
    keyToSendPQ: Uint8Array;
    indexToSend: number;
    session: Session;
    pqSessionKey: CryptoKey;
    kemSecret: Uint8Array;
    constructor(olmKey: Uint8Array, pqKey: Uint8Array, index: number) {
        this.status = PROTOCOL_STATUS.READY_TO_START;
        this.session = null as any;
        this.pqSessionKey = null as any;
        this.keyToSendOlm = olmKey;
        this.keyToSendPQ = pqKey;
        this.indexToSend = index;
    }
    cleanKeyInfo() {
        this.commitment = "";
        this.kemSecret = new Uint8Array();
        this.keyToSendOlm = new Uint8Array();
        this.keyToSendPQ = new Uint8Array();
        this.indexToSend = -1;
    }
    encryptKeyInfo() {
        return this.encryptGivenKeyInfo(this.keyToSendOlm, this.indexToSend);
    }
    encryptGivenKeyInfo(key: Uint8Array, index: number): EncryptedOlmMessage {
        const message = new Uint8Array(key.length + 1);
        message.set(key, 0);
        message.set([index], key.length);
        return this.session.encrypt(message);
    }

    decryptKeyInfo(message_type: number, ciphertext: string) {
        const result = this.session.decrypt(message_type, ciphertext);
        const index = result[result.length - 1];
        const key = result.slice(0, -1);
        return { key, index };
    }
}

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
    private readonly _olmDataMap: Map<string, OlmData>;

    constructor(id: string) {
        this._myId = id;
        this._mediaKeyOlm = new Uint8Array();
        this._mediaKeyPQ = new Uint8Array();
        this._mediaKeyIndex = -1;
        this._publicKyberKeyBase64 = "";
        this._privateKyberKey = new Uint8Array();
        this._publicCurve25519Key = "";
        this._indenityKeyCommitment = "";
        this._olmDataMap = new Map<string, OlmData>();

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
        olmData: OlmData,
    ): Promise<KeyInfo> {
        try {
            const pqCiphertext = await encryptKeyInfoPQ(
                olmData.pqSessionKey,
                this._mediaKeyPQ,
            );
            const olmCiphertext = olmData.encryptGivenKeyInfo(
                this._mediaKeyOlm,
                this._mediaKeyIndex,
            );

            const data: KeyInfo = {
                ciphertext: olmCiphertext.ciphertext,
                message_type: olmCiphertext.message_type,
                pqCiphertext: pqCiphertext,
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
            console.info(`E2E: Generated ${keys.length} one-time keys`);
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
            let shouldRatchet = false;
            const olmData = this._getParticipantOlmData(pId);
            const status = olmData.status;

            if (
                status === PROTOCOL_STATUS.DONE ||
                status === PROTOCOL_STATUS.WAITING_DONE
            ) {
                shouldRatchet = true;
            }
            return shouldRatchet;
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
            const status = olmData.status;
            let data = undefined;

            if (
                status === PROTOCOL_STATUS.DONE ||
                status === PROTOCOL_STATUS.WAITING_DONE
            ) {
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
            olmData.status = PROTOCOL_STATUS.TERMINATED;

            if (olmData.session) {
                olmData.session.free();
                olmData.session = undefined;
            }
        } catch (error) {
            console.error(
                `E2E: Failed to clear session for participat ${pId}: ${error}`,
            );
        }
    }

    _getParticipantOlmData(pId: string): OlmData {
        let result = this._olmDataMap.get(pId);
        if (!result) {
            result = new OlmData(
                this._mediaKeyOlm,
                this._mediaKeyPQ,
                this._mediaKeyIndex,
            );
            this._olmDataMap.set(pId, result);
        }
        return result;
    }

    async _onConferenceLeft(participants: JitsiParticipant[]) {
        for (const participant of participants) {
            this.clearParticipantSession(participant.getId());
        }

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
            if (olmData.status === PROTOCOL_STATUS.READY_TO_START) {
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

                const commitmentToKeys = await commitToMediaKeyShares(
                    this._myId,
                    olmData.keyToSendOlm,
                    olmData.keyToSendPQ,
                    olmData.indexToSend,
                );

                const ciphertext = olmData.session.encrypt(
                    new TextEncoder().encode(commitmentToKeys),
                );

                const data: PQsessionInit = {
                    encapsKyber: encapsulatedBase64,
                    publicKey: this._publicCurve25519Key,
                    publicKyberKey: this._publicKyberKeyBase64,
                    ciphertext: ciphertext.ciphertext,
                    message_type: ciphertext.message_type,
                };

                olmData.status = PROTOCOL_STATUS.WAITING_PQ_SESSION_ACK;
                return { data, keyCommitment };
            } else {
                throw new Error(`Protocol status is ${olmData.status}`);
            }
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
        message_type: number,
    ): Promise<{ data: PQsessionAck; keyCommitment: string }> {
        try {
            const olmData = this._getParticipantOlmData(pId);

            if (olmData.status === PROTOCOL_STATUS.WAITING_PQ_SESSION_INIT) {
                const keyCommitment = await commitToIdentityKeys(
                    pId,
                    publicKyberKey,
                    publicKey,
                );

                const { plaintext, session } =
                    this._olmAccount.create_inbound_session(
                        publicKey,
                        message_type,
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

                olmData.pqSessionKey = await deriveEncryptionKey(
                    decapsulatedSecret,
                    sharedSecret,
                );

                const pqEncKeyInfo = await encryptKeyInfoPQ(
                    olmData.pqSessionKey,
                    olmData.keyToSendPQ,
                );

                const olmEncKeyInfo = olmData.encryptKeyInfo();

                const data: PQsessionAck = {
                    encapsKyber: encapsulatedBase64,
                    ciphertext: olmEncKeyInfo.ciphertext,
                    message_type: olmEncKeyInfo.message_type,
                    pqCiphertext: pqEncKeyInfo,
                };

                olmData.status = PROTOCOL_STATUS.WAITING_SESSION_ACK;
                return { data, keyCommitment };
            } else {
                throw new Error(`Protocol status is ${olmData.status}`);
            }
        } catch (error) {
            throw new Error(`E2E: replyToPQSessionInit failed: ${error}`);
        }
    }

    async createSessionAckMessage(
        pId: string,
        encapsKyber: string,
        ciphertext: string,
        message_type: number,
        pqCiphertext: string,
    ): Promise<{
        data: SessionAck;
        olmKey: Uint8Array;
        pqKey: Uint8Array;
        index: number;
    }> {
        try {
            const olmData = this._getParticipantOlmData(pId);

            if (olmData.status === PROTOCOL_STATUS.WAITING_PQ_SESSION_ACK) {
                const decapsulatedSecret = await decapsulateSecret(
                    encapsKyber,
                    this._privateKyberKey,
                );

                olmData.pqSessionKey = await deriveEncryptionKey(
                    olmData.kemSecret,
                    decapsulatedSecret,
                );
                const { key, index } = olmData.decryptKeyInfo(
                    message_type,
                    ciphertext,
                );

                const pqKey = await decryptKeyInfoPQ(
                    pqCiphertext,
                    olmData.pqSessionKey,
                );

                const commitment = await commitToMediaKeyShares(
                    pId,
                    key,
                    pqKey,
                    index,
                );

                if (olmData.commitment != commitment) {
                    throw new Error(`Keys do not match the commitment.`);
                } else {
                    console.info(
                        `E2E: Recived new keys from ${pId}, index = ${index}`,
                    );

                    const olmCiphertext = olmData.encryptKeyInfo();
                    const pqCiphertextBase64 = await encryptKeyInfoPQ(
                        olmData.pqSessionKey,
                        olmData.keyToSendPQ,
                    );

                    console.info(
                        `E2E: Sent my keys to ${pId}, index = ${this._mediaKeyIndex}.`,
                    );

                    const data: SessionAck = {
                        ciphertext: olmCiphertext.ciphertext,
                        message_type: olmCiphertext.message_type,
                        pqCiphertext: pqCiphertextBase64,
                    };

                    olmData.status = PROTOCOL_STATUS.WAITING_DONE;
                    return { data, olmKey: key, pqKey: pqKey, index: index };
                }
            } else {
                throw new Error(`Protocol status is ${olmData.status}`);
            }
        } catch (error) {
            throw new Error(`E2E: replyToPQSessionAck failed: ${error}`);
        }
    }

    async createSessionDoneMessage(
        pId: string,
        ciphertext: string,
        message_type: number,
        pqCiphertext: string,
    ): Promise<{
        data: KeyInfo | undefined;
        olmKey: Uint8Array;
        pqKey: Uint8Array;
        index: number;
    }> {
        try {
            const olmData = this._getParticipantOlmData(pId);
            if (olmData.status === PROTOCOL_STATUS.WAITING_SESSION_ACK) {
                const { key, index } = olmData.decryptKeyInfo(
                    message_type,
                    ciphertext,
                );

                const pqKey = await decryptKeyInfoPQ(
                    pqCiphertext,
                    olmData.pqSessionKey,
                );

                const commitment = await commitToMediaKeyShares(
                    pId,
                    key,
                    pqKey,
                    index,
                );
                let data = undefined;
                if (olmData.commitment != commitment) {
                    throw new Error(`Keys do not match the commitment.`);
                } else {
                    console.info(
                        `E2E: Recived new keys from ${pId}, index = ${index}`,
                    );

                    olmData.status = PROTOCOL_STATUS.DONE;
                    if (olmData.indexToSend != this._mediaKeyIndex) {
                        console.info(
                            `E2E: Keys changes during session-init, sending new keys to ${pId}.`,
                        );
                        data = await this.createKeyInfoMessage(pId, olmData);
                    }
                    olmData.cleanKeyInfo();
                }
                return { data, olmKey: key, pqKey: pqKey, index: index };
            } else {
                throw new Error(`Protocol status is ${olmData.status}`);
            }
        } catch (error) {
            throw new Error(`E2E: replyToSessionAck failed: ${error}`);
        }
    }

    async processSessionDoneMessage(pId: string): Promise<KeyInfo | undefined> {
        try {
            const olmData = this._getParticipantOlmData(pId);
            let data = undefined;
            if (olmData.status === PROTOCOL_STATUS.WAITING_DONE) {
                if (olmData.indexToSend != this._mediaKeyIndex) {
                    console.info(
                        `E2E: Keys changes during session-init, sending new keys to ${pId}.`,
                    );
                    data = await this.createKeyInfoMessage(pId, olmData);
                }
                olmData.cleanKeyInfo();
                console.info(
                    `E2E: Participant ${pId} established E2E channel with us.`,
                );
            } else {
                throw new Error(`Protocol status is ${olmData.status}`);
            }
            return data;
        } catch (error) {
            throw new Error(`E2E: replyToSessionAck failed: ${error}`);
        }
    }

    async processKeyInfoMessage(
        pId: string,
        ciphertext: string,
        message_type: number,
        pqCiphertext: string,
    ): Promise<{ olmKey: Uint8Array; pqKey: Uint8Array; index: number }> {
        try {
            const olmData = this._getParticipantOlmData(pId);
            if (
                olmData.status === PROTOCOL_STATUS.DONE ||
                olmData.status === PROTOCOL_STATUS.WAITING_DONE
            ) {
                const { key, index } = olmData.decryptKeyInfo(
                    message_type,
                    ciphertext,
                );
                const pqKey = await decryptKeyInfoPQ(
                    pqCiphertext,
                    olmData.pqSessionKey,
                );

                return { olmKey: key, pqKey: pqKey, index: index };
            } else {
                throw new Error(`Protocol status is ${olmData.status}`);
            }
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
            if (olmData.status === PROTOCOL_STATUS.READY_TO_START) {
                console.info(
                    `E2E: Sending session-init to participant ${pId} `,
                );

                const commitmentToKeys = await commitToMediaKeyShares(
                    this._myId,
                    olmData.keyToSendOlm,
                    olmData.keyToSendPQ,
                    olmData.indexToSend,
                );

                const data: SessionInit = {
                    otKey,
                    publicKey: this._publicCurve25519Key,
                    publicKyberKey: this._publicKyberKeyBase64,
                    commitment: commitmentToKeys,
                };

                olmData.status = PROTOCOL_STATUS.WAITING_PQ_SESSION_INIT;
                return data;
            } else {
                throw new Error(`Protocol status is ${olmData.status}`);
            }
        } catch (error) {
            throw new Error(`E2E: createSessionInitMessage failed: ${error}`);
        }
    }
}
