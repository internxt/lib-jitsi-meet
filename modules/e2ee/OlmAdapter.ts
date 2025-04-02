import initVodozemac, { Account, Session, EncryptedOlmMessage } from '../../vodozemac-wasm/vodozemac';

import Listenable from "../util/Listenable";
import { FEATURE_E2EE, JITSI_MEET_MUC_TYPE } from "../xmpp/xmpp";

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
    computeCommitment,
    deriveEncryptionKey,
    commitToSecret,
} from "./crypto-workers";
import JitsiConference from "../../JitsiConference";
import JitsiParticipant from "../../JitsiParticipant";
import {
    MEDIA_KEY_LEN,
    OLM_MESSAGE_TYPE,
    OLM_MESSAGE_TYPES,
    PROTOCOL_STATUS,
    REQ_TIMEOUT,
} from "./Constants";

type ProtocolStatus = (typeof PROTOCOL_STATUS)[keyof typeof PROTOCOL_STATUS];

const kOlmData = "OlmData";
const OlmAdapterEvents = {
    PARTICIPANT_KEY_RATCHET: "olm.partitipant_key_ratchet",
    PARTICIPANT_KEY_UPDATED: "olm.partitipant_key_updated",
    PARTICIPANT_KEYS_COMMITMENT: "olm.participant_keys_committed",
};

class OlmData {
    status: ProtocolStatus;
    commitment: string;
    private keyToSendOlm: Uint8Array;
    private keyToSendPQ: Uint8Array;
    private indexToSend: number;
    session: Session;
    pqSessionKey: CryptoKey;
    kemSecret: Uint8Array;
    reSendKeyInfo: boolean;
    constructor() {
        this.status = PROTOCOL_STATUS.READY_TO_START;
        this.session = null as any;
        this.pqSessionKey = null as any;
        this.cleanKeyInfo();
    }
    cleanKeyInfo() {
        this.commitment = "";
        this.reSendKeyInfo = false;
        this.kemSecret = new Uint8Array();
        this.keyToSendOlm = new Uint8Array();
        this.keyToSendPQ = new Uint8Array();
        this.indexToSend = -1;
    }
    async setKeyInfo(
        id: string,
        olmKey: Uint8Array,
        pqKey: Uint8Array,
        index: number,
    ) {
        this.keyToSendOlm = olmKey;
        this.keyToSendPQ = pqKey;
        this.indexToSend = index;
        return commitToSecret(
            id,
            this.keyToSendOlm,
            this.keyToSendPQ,
            this.indexToSend,
        );
    }

    async setPQSessionKey(key1, key2) {
        this.pqSessionKey = await deriveEncryptionKey(key1, key2);
    }

    async encryptPQKeyInfo() {
        return this.encryptGivenPQKeyInfo(this.keyToSendPQ);
    }

    async decryptPQKeyInfo(ciphertext: string) {
        return decryptKeyInfoPQ(ciphertext, this.pqSessionKey);
    }

    async encryptGivenPQKeyInfo(key: Uint8Array) {
        return encryptKeyInfoPQ(this.pqSessionKey, key);
    }

    encryptKeyInfo() {
        return this.encryptGivenKeyInfo(this.keyToSendOlm, this.indexToSend);
    }
    encryptGivenKeyInfo(key: Uint8Array, index: number): EncryptedOlmMessage {
        const message = new Uint8Array(MEDIA_KEY_LEN+ 1);
        message.set(key, 0);
        message.set([index], MEDIA_KEY_LEN); 
        return this.session.encrypt(message);
    }

    decryptKeyInfo(message_type: number, ciphertext: string) {
        const result = this.session.decrypt(
            message_type,
            ciphertext,
        );
        const index = result[result.length - 1]; 
        const key = result.slice(0, -1);
        return { key, index };
    }
}
/**
 * This class implements an End-to-End Encrypted communication channel between every two peers
 * in the conference. This channel uses libolm to achieve E2EE.
 *
 * The created channel is then used to exchange the secret key that each participant will use
 * to encrypt the actual media (see {@link E2EEContext}).
 *
 * A simple JSON message based protocol is implemented, which follows a request - response model:
 * - session-init: Initiates an olm session establishment procedure, sends public Kyber key. This message will be sent
 *                 by the participant who just joined, to everyone else.
 * - pq-session-init: Starts a PQ session establishment procedure. Completes the olm session etablishment.
 * - pq-session-ack: Initiates a PQ session establishment procedure.
 * - session-ack:  This messsage may contain ancilliary
 *                encrypted data, more specifically the sender's current key.
 * - key-info: Includes the sender's most up to date key information.
 * - error: Indicates a request processing error has occurred.
 *
 * These requessts and responses are transport independent. Currently they are sent using XMPP
 * MUC private messages.
 */
export class OlmAdapter extends Listenable {
    private readonly _conf: JitsiConference;
    private _olmInitialized: boolean;
    private _mediaKeyOlm: Uint8Array;
    private _mediaKeyPQ: Uint8Array;
    private _mediaKeyIndex: number;
    private readonly _reqs: Map<
        string,
        { resolve: (args?: unknown) => void; reject?: (args?: unknown) => void }
    >;
    private _publicKyberKeyBase64: string;
    private _privateKyberKey: Uint8Array;
    private _olmAccount: Account;
    private _publicCurve25519Key: string;
    private _indenityKeyCommitment: string;
    static events: {
        PARTICIPANT_KEY_RATCHET: string;
        PARTICIPANT_KEY_UPDATED: string;
        PARTICIPANT_KEYS_COMMITMENT: string;
    };

    emit(event: string, ...args: any[]) {
        super.emit(event, ...args);
    }

    /**
     * Creates an adapter instance for the given conference.
     */
    constructor(conference: JitsiConference) {
        super();
        this._conf = conference;
        this._mediaKeyOlm = new Uint8Array();
        this._mediaKeyPQ = new Uint8Array();
        this._mediaKeyIndex = -1;
        this._reqs = new Map();
        this._publicKyberKeyBase64 = "";
        this._privateKyberKey = new Uint8Array();
        this._publicCurve25519Key = "";
        this._indenityKeyCommitment = "";

        this._olmInitialized = false;
    }

    /**
     * Initializes the Olm library and sets up the account.
     * This includes setting up cryptographic keys.
     *
     * @returns {Promise<boolean>}  Returns true when initialization is complete.
     * @private
     */
    async init() {
        try {
            if (!this._olmInitialized) {
                await initVodozemac();

                this._olmAccount = new Account();
                this._publicCurve25519Key = this._olmAccount.curve25519_key;

                const { publicKeyBase64, privateKey } =
                    await generateKyberKeys();
                this._publicKyberKeyBase64 = publicKeyBase64;
                this._privateKyberKey = privateKey;
                this._indenityKeyCommitment = await computeCommitment(
                    this._publicKyberKeyBase64,
                    this._publicCurve25519Key,
                );
                this._olmInitialized = true;
            }
        } catch (error) {
            throw new Error(`E2E:  Failed to initialize Olm: ${error}`);
        }
    }

    /**
     * Returns the current participants conference ID.
     *
     * @returns {string}
     * @private
     */
    get myId(): string {
        return this._conf.myUserId();
    }

    /**
     * Sends KEY_INFO message to the participant.
     *
     * @param {JitsiParticipant} participant
     * @returns {Promise<void>}  Resolves when KEY_INFO message is sent.
     * @private
     */
    async sendKeyInfoToParticipant(pId: string, olmData: OlmData) {
        try {
            const pqCiphertext = await olmData.encryptGivenPQKeyInfo(
                this._mediaKeyPQ,
            );
            const olmCiphertext = olmData.encryptGivenKeyInfo(
                this._mediaKeyOlm,
                this._mediaKeyIndex,
            );
            this._sendKeyInfoMessage(olmCiphertext, pqCiphertext, pId);
        } catch (error) {
            this._sendError(
                pId,
                `Sending KEY_INFO failed for participant ${pId}: ${error}`,
            );
        }
    }

    /**
     * Starts new olm sessions with every other participant that has the participantId "smaller" the localParticipantId.
     *
     * @private
     */
    async initSessions(): Promise<Promise<unknown>[]> {
        if (!this._olmInitialized) {
            throw new Error(
                "E2E: Cannot init sessions because olm was not initialized",
            );
        }
        try {
            const localParticipantId = this.myId;
            this._onKeysCommitment(
                localParticipantId,
                this._indenityKeyCommitment,
            );
            this._mediaKeyOlm = generateKey();
            this._mediaKeyPQ = generateKey();
            this._mediaKeyIndex = 0;

            this._onKeysUpdated(
                localParticipantId,
                this._mediaKeyOlm,
                this._mediaKeyPQ,
                this._mediaKeyIndex,
            );

            const participants = this._conf.getParticipants();
            const list = participants.filter(
                (participant) =>
                    participant.hasFeature(FEATURE_E2EE) &&
                    localParticipantId > participant.getId(),
            );
            console.info(
                `E2E: My ID is ${localParticipantId}, should send session-init to smaller IDs: [ ${list.map((p) => p.getId())}]`,
            );
            this._olmAccount.generate_one_time_keys(list.length);
            const keys = Array.from(this._olmAccount.one_time_keys.values());
    
            const promises = list.map((participant) => {
                const lastKey = keys.pop() as string;
                this._sendSessionInit(participant, lastKey);

                const pId = participant.getId();
                const sessionPromise = new Promise((resolve, reject) => {
                    this._reqs.set(pId, { resolve, reject });
                });

                const timeoutPromise = new Promise((_, reject) =>
                    setTimeout(
                        () =>
                            reject(new Error("Session init request timed out")),
                        REQ_TIMEOUT,
                    ),
                );

                // Simulates timeout with deferred object but using promises
                return Promise.race([sessionPromise, timeoutPromise])
                    .then((result) => {
                        console.info(
                            `E2E: Session with ${pId} initialized successfully.`,
                        );
                        return result;
                    })
                    .catch((error) => {
                        this._reqs.delete(pId);
                        console.error(
                            `E2E: Failed to initialize session with ${pId}: ${error}`,
                        );
                    });
            });

            return promises;
        } catch (error) {
            throw new Error(`E2E: Failed to initialize sessions: ${error}`);
        }
    }

    /**
     * Advances the current key by using ratcheting.
     *
     * @private
     */
    async _ratchetKeyImpl() {
        try {
            this._mediaKeyOlm = await ratchetKey(this._mediaKeyOlm);
            this._mediaKeyPQ = await ratchetKey(this._mediaKeyPQ);
            this._mediaKeyIndex++;
            this._onKeysUpdated(
                this.myId,
                this._mediaKeyOlm,
                this._mediaKeyPQ,
                this._mediaKeyIndex,
            );
            for (const participant of this._conf.getParticipants()) {
                const olmData = this._getParticipantOlmData(participant);
                const pId = participant.getId();
                const status = olmData.status;

                if (
                    status != PROTOCOL_STATUS.DONE &&
                    status != PROTOCOL_STATUS.READY_TO_START
                ) {
                    olmData.reSendKeyInfo = true;
                }

                if (
                    status == PROTOCOL_STATUS.DONE ||
                    status == PROTOCOL_STATUS.WAITING_DONE
                ) {
                    this.emit(OlmAdapterEvents.PARTICIPANT_KEY_RATCHET, pId);
                }
            }
        } catch (error) {
            throw new Error(`Key ratchet failed: ${error}`);
        }
    }

    /**
     *  Rotates the participant keys
     *
     * @private
     */
    async _rotateKeyImpl() {
        try {
            console.info("E2E: Rotating my keys");
            this._mediaKeyOlm = generateKey();
            this._mediaKeyPQ = generateKey();
            this._mediaKeyIndex++;
            this._onKeysUpdated(
                this.myId,
                this._mediaKeyOlm,
                this._mediaKeyPQ,
                this._mediaKeyIndex,
            );
            for (const participant of this._conf.getParticipants()) {
                const olmData = this._getParticipantOlmData(participant);
                const pId = participant.getId();
                const status = olmData.status;

                if (
                    status != PROTOCOL_STATUS.DONE &&
                    status != PROTOCOL_STATUS.READY_TO_START
                ) {
                    olmData.reSendKeyInfo = true;
                }

                if (
                    status == PROTOCOL_STATUS.DONE ||
                    status == PROTOCOL_STATUS.WAITING_DONE
                ) {
                    this.sendKeyInfoToParticipant(pId, olmData);
                }
            }
        } catch (error) {
            throw new Error(`Key rotation failed: ${error}`);
        }
    }

    /**
     * Frees the olmData session for the given participant.
     *
     *  @param {JitsiParticipant} participant - The participant.
     *  @private
     */
    clearParticipantSession(participant: JitsiParticipant) {
        try {
            const olmData = this._getParticipantOlmData(participant);

            if (olmData.session) {
                olmData.session.free();
                olmData.session = undefined;
            }
            olmData.status = PROTOCOL_STATUS.TERMINATED;
        } catch (error) {
            console.error(
                `E2E: Failed to clear session for participat ${participant.getId()}: ${error}`,
            );
        }
    }

    /**
     * Frees the olmData sessions for all participants.
     *
     * @private
     */
    clearAllParticipantsSessions() {
        for (const participant of this._conf.getParticipants()) {
            this.clearParticipantSession(participant);
        }
    }

    /**
     * Computes commitment to the keys and sends it to the web workers
     * @private
     */
    async _onKeysCommitment(pId: string, commitment: string) {
        this.emit(
            OlmAdapterEvents.PARTICIPANT_KEYS_COMMITMENT,
            pId,
            commitment,
        );
    }

    async _onKeysUpdated(
        id: string,
        olmKey: Uint8Array,
        pqKey: Uint8Array,
        index: number,
    ) {
        this.emit(
            OlmAdapterEvents.PARTICIPANT_KEY_UPDATED,
            id,
            olmKey,
            pqKey,
            index,
        );
    }

    /**
     * Internal helper for getting the olm related data associated with a participant.
     *
     * @param {JitsiParticipant} participant - Participant whose data wants to be extracted.
     * @returns {Object}
     * @private
     */
    _getParticipantOlmData(participant: JitsiParticipant): OlmData {
        participant[kOlmData] = participant[kOlmData] || new OlmData();
        const data = participant[kOlmData];
        return data;
    }

    /**
     * Handles leaving the conference, cleaning up olm sessions.
     *
     * @private
     */
    async _onConferenceLeft() {
        if (this._olmInitialized) {
            for (const participant of this._conf.getParticipants()) {
                this.clearParticipantSession(participant);
            }

            if (this._olmAccount) {
                this._olmAccount.free();
                this._olmAccount = undefined;
            }
        }
    }

    /**
     * Sends errors resulting from a mismatch of protocol status and recived message
     *
     * @private
     */
    async _sendStatusError(
        participantID: string,
        protocolStatus: string,
        recivedMessageType: string,
    ): Promise<void> {
        this._sendError(
            participantID,
            `Got ${recivedMessageType} from ${participantID} but protocol status is ${protocolStatus}`,
        );
    }
    /**
     * Sends SESSION_INIT message
     *
     * @private
     */
    async _sendSessionInitMessage(
        otKey: string,
        commitment: string,
        pId: string,
    ): Promise<void> {
        const publicKey = this._publicCurve25519Key;
        const publicKyberKey = this._publicKyberKeyBase64;
        const init = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.SESSION_INIT,
                data: {
                    otKey,
                    publicKey,
                    publicKyberKey,
                    commitment,
                },
            },
        };
        this._sendMessage(init, pId);
    }

    async _sendSessionDoneMessage(pId: string): Promise<void> {
        const init = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.SESSION_DONE,
                data: {},
            },
        };
        this._sendMessage(init, pId);
    }

    /**
     * Sends PQ_SESSION_INIT message
     *
     * @private
     */
    async _sendPQSessionInitMessage(
        encapsKyber: string,
        ciphertext: EncryptedOlmMessage,
        pId: string,
    ): Promise<void> {
        const publicKey = this._publicCurve25519Key;
        const publicKyberKey = this._publicKyberKeyBase64;
        const ack = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.PQ_SESSION_INIT,
                data: {
                    encapsKyber,
                    publicKey,
                    publicKyberKey,
                    ciphertext: ciphertext.ciphertext,
                    message_type: ciphertext.message_type,
                },
            },
        };

        this._sendMessage(ack, pId);
    }

    /**
     * Sends PQ_SESSION_ACK message
     *
     * @private
     */
    async _sendPQSessionAckMessage(
        encapsKyber: string,
        ciphertext: EncryptedOlmMessage,
        pqCiphertext: string,
        pId: string,
    ): Promise<void> {
        const ack = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.PQ_SESSION_ACK,
                data: {
                    encapsKyber,
                    ciphertext: ciphertext.ciphertext,
                    message_type: ciphertext.message_type,
                    pqCiphertext,
                },
            },
        };
        this._sendMessage(ack, pId);
    }

    /**
     * Sends SESSION_ACK message
     *
     * @private
     */
    async _sendSessionAckMessage(
        ciphertext: EncryptedOlmMessage,
        pqCiphertext: string,
        pId: string,
    ): Promise<void> {
        const ack = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.SESSION_ACK,
                data: {
                    ciphertext: ciphertext.ciphertext,
                    message_type: ciphertext.message_type,
                    pqCiphertext,
                },
            },
        };

        this._sendMessage(ack, pId);
    }

    /**
     * Sends KEY_INFO message
     *
     * @private
     */
    async _sendKeyInfoMessage(
        ciphertext: EncryptedOlmMessage,
        pqCiphertext: string,
        pId: string,
    ): Promise<void> {
        const info = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.KEY_INFO,
                data: {
                    ciphertext: ciphertext.ciphertext,
                    message_type: ciphertext.message_type,
                    pqCiphertext,
                },
            },
        };
        console.info(`E2E: Sending KEY_INFO to the participant ${pId}`);
        this._sendMessage(info, pId);
    }

    /**
     * Main message handler. Handles 1-to-1 messages received from other participants
     * and send the appropriate replies.
     *
     * @private
     */
    async _onEndpointMessageReceived(participant: JitsiParticipant, payload) {
        if (payload[JITSI_MEET_MUC_TYPE] !== OLM_MESSAGE_TYPE || !payload.olm) {
            console.warn("E2E: Invalid or missing olm payload");
            return;
        }
        const msg = payload.olm;
        const pId = participant.getId();

        try {
            if (! this._olmInitialized) {
                throw new Error("Olm not initialized");
            }

            const olmData = this._getParticipantOlmData(participant);

            switch (msg.type) {
                case OLM_MESSAGE_TYPES.SESSION_INIT: {
                    if (olmData.status === PROTOCOL_STATUS.READY_TO_START) {
                        const { otKey, publicKey, publicKyberKey, commitment } =
                            msg.data;
                        olmData.commitment = commitment;
                        const keyCommitment = await computeCommitment(
                            publicKyberKey,
                            publicKey,
                        );
                        this._onKeysCommitment(pId, keyCommitment);
                        olmData.session = this._olmAccount.create_outbound_session(
                            publicKey,
                            otKey,
                        );

                        const { encapsulatedBase64, sharedSecret } =
                            await encapsulateSecret(publicKyberKey);
                        olmData.kemSecret = sharedSecret;

                        const commitmentToKeys = await olmData.setKeyInfo(
                            this.myId,
                            this._mediaKeyOlm,
                            this._mediaKeyPQ,
                            this._mediaKeyIndex,
                        );

                        const ciphertext = olmData.session.encrypt(new TextEncoder().encode(commitmentToKeys));
                           
                        this._sendPQSessionInitMessage(
                            encapsulatedBase64,
                            ciphertext,
                            pId,
                        );

                        olmData.status = PROTOCOL_STATUS.WAITING_PQ_SESSION_ACK;
                    } else this._sendStatusError(pId, msg.type, olmData.status);
                    break;
                }

                case OLM_MESSAGE_TYPES.PQ_SESSION_INIT: {
                    if (
                        olmData.status ===
                        PROTOCOL_STATUS.WAITING_PQ_SESSION_INIT
                    ) {
                        const {
                            encapsKyber,
                            publicKey,
                            publicKyberKey,
                            ciphertext,
                            message_type,
                        } = msg.data;

                        
                        const keyCommitment = await computeCommitment(
                            publicKyberKey,
                            publicKey,
                        );
                        this._onKeysCommitment(pId, keyCommitment);


                        const { plaintext, session } = this._olmAccount.create_inbound_session(
                            publicKey as string,
                            message_type as number,
                            ciphertext as string,
                        );
        
                        olmData.session = session;
                        olmData.commitment = new TextDecoder().decode(plaintext);

                        const decapsulatedSecret = await decapsulateSecret(
                            encapsKyber,
                            this._privateKyberKey,
                        );

                        const { encapsulatedBase64, sharedSecret } =
                            await encapsulateSecret(publicKyberKey);
                        
                        await olmData.setPQSessionKey(
                            decapsulatedSecret,
                            sharedSecret,
                        );

                        const pqEncKeyInfo =
                            await olmData.encryptPQKeyInfo();
                        const olmEncKeyInfo = olmData.encryptKeyInfo();

                        this._sendPQSessionAckMessage(
                            encapsulatedBase64,
                            olmEncKeyInfo,
                            pqEncKeyInfo,
                            pId,
                        );
                        olmData.status = PROTOCOL_STATUS.WAITING_SESSION_ACK;
                    } else this._sendStatusError(pId, msg.type, olmData.status);
                    break;
                }
                case OLM_MESSAGE_TYPES.PQ_SESSION_ACK: {
                    if (
                        olmData.status ===
                        PROTOCOL_STATUS.WAITING_PQ_SESSION_ACK
                    ) {
                        const { encapsKyber, ciphertext, message_type, pqCiphertext } =
                            msg.data;

                        const decapsulatedSecret = await decapsulateSecret(
                            encapsKyber,
                            this._privateKyberKey,
                        );

                        await olmData.setPQSessionKey(
                            olmData.kemSecret,
                            decapsulatedSecret,
                        );
                        const { key, index } =
                            olmData.decryptKeyInfo(message_type, ciphertext);

                        const pqKey =
                            await olmData.decryptPQKeyInfo(pqCiphertext);

                        const commitment = await commitToSecret(
                            pId,
                            key,
                            pqKey,
                            index,
                        );

                        if (olmData.commitment != commitment) {
                            this._sendError(
                                pId,
                                `Keys do not match the commitment.`,
                            );
                        } else {
                            console.info(
                                `E2E: Recived new keys from ${pId}, index = ${index}`,
                            );
                            this._onKeysUpdated(pId, key, pqKey, index);

                            const olmCiphertext = olmData.encryptKeyInfo();
                            const pqCiphertextBase64 =
                                await olmData.encryptPQKeyInfo();

                            console.info(
                                `E2E: Sent my keys to ${pId}, index = ${this._mediaKeyIndex}.`,
                            );
                            this._sendSessionAckMessage(
                                olmCiphertext,
                                pqCiphertextBase64,
                                pId,
                            );

                            olmData.status = PROTOCOL_STATUS.WAITING_DONE;
                        }
                    } else this._sendStatusError(pId, msg.type, olmData.status);
                    break;
                }
                case OLM_MESSAGE_TYPES.SESSION_ACK: {
                    if (
                        olmData.status === PROTOCOL_STATUS.WAITING_SESSION_ACK
                    ) {
                        const { ciphertext, message_type, pqCiphertext } = msg.data;

                        const { key, index } =
                            olmData.decryptKeyInfo(message_type, ciphertext);

                        const pqKey =
                            await olmData.decryptPQKeyInfo(pqCiphertext);

                        const commitment = await commitToSecret(
                            pId,
                            key,
                            pqKey,
                            index,
                        );

                        if (olmData.commitment != commitment) {
                            this._sendError(
                                pId,
                                `Keys do not match the commitment.`,
                            );
                            console.warn(`E2E: Rotating my keys.`);
                            await this._rotateKeyImpl();
                        } else {
                            console.info(
                                `E2E: Recived new keys from ${pId}, index = ${index}`,
                            );
                            this._onKeysUpdated(pId, key, pqKey, index);

                            olmData.status = PROTOCOL_STATUS.DONE;
                            if (olmData.reSendKeyInfo) {
                                console.info(
                                    `E2E: Keys changes during session-init, sending new keys to ${pId}.`,
                                );
                                this.sendKeyInfoToParticipant(pId, olmData);
                            }
                            olmData.cleanKeyInfo();
                            this._sendSessionDoneMessage(pId);

                            const requestPromise = this._reqs.get(pId);
                            if (requestPromise) {
                                requestPromise.resolve();
                                this._reqs.delete(pId);
                            } else
                                console.warn(
                                    `E2E: Session with ${pId} was established after reaching time out.`,
                                );
                        }
                    } else this._sendStatusError(pId, msg.type, olmData.status);
                    break;
                }
                case OLM_MESSAGE_TYPES.ERROR: {
                    console.error(msg.data.error);
                    break;
                }
                case OLM_MESSAGE_TYPES.SESSION_DONE: {
                    if (olmData.status === PROTOCOL_STATUS.WAITING_DONE) {
                        if (olmData.reSendKeyInfo) {
                            console.info(
                                `E2E: Keys changes during session-init, sending new keys to ${pId}.`,
                            );
                            this.sendKeyInfoToParticipant(pId, olmData);
                        }
                        olmData.cleanKeyInfo();
                        console.info(
                            `E2E: Participant ${pId} established E2E channel with us.`,
                        );
                    } else this._sendStatusError(pId, msg.type, olmData.status);
                    break;
                }
                case OLM_MESSAGE_TYPES.KEY_INFO: {
                    if (
                        olmData.status === PROTOCOL_STATUS.DONE ||
                        olmData.status === PROTOCOL_STATUS.WAITING_DONE
                    ) {
                        const { ciphertext, message_type, pqCiphertext } = msg.data;
                        const { key, index } =
                            olmData.decryptKeyInfo(message_type, ciphertext);
                        const pqKey =
                            await olmData.decryptPQKeyInfo(pqCiphertext);
                        this._onKeysUpdated(pId, key, pqKey, index);
                    } else {
                        console.warn(
                            `E2E: KEY_INFO from ${pId} arrived before session is established, re-sending`,
                        );
                        this._sendMessage(msg, this.myId);
                    }
                    break;
                }
            }
        } catch (error) {
            this._sendError(
                pId,
                `Processing ${msg.type} failed for ${pId}: ${error}`,
            );
        }
    }

    /**
     * Builds and sends an error message to the target participant.
     *
     * @param {string} id - The target participant.
     * @param {string} error - The error message.
     * @returns {void}
     */
    _sendError(pId: string, error: string) {
        console.error(`E2E: ${error}`);
        const err = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.ERROR,
                data: {
                    error,
                },
            },
        };

        this._sendMessage(err, pId);
    }

    /**
     * Internal helper to send the given object to the given participant ID.
     * This function merely exists so the transport can be easily swapped.
     * Currently messages are transmitted via XMPP MUC private messages.
     *
     * @param {object} data - The data that will be sent to the target participant.
     * @param {string} participantId - ID of the target participant.
     */
    _sendMessage(data, participantId: string) {
        this._conf.sendMessage(data, participantId);
    }

    /**
     * Builds and sends the session-init request to the target participant.
     *
     * @param {JitsiParticipant} participant - Participant to whom we'll send the request.
     * @returns {Promise} - The promise will be resolved when the session-ack is received.
     * @private
     */
    async _sendSessionInit(participant: JitsiParticipant, otKey: string) {
        try {
            const olmData = this._getParticipantOlmData(participant);
            const pId = participant.getId();
            console.info(`E2E: Sending session-init to participant ${pId} `);

            const commitmentToKeys = await olmData.setKeyInfo(
                this.myId,
                this._mediaKeyOlm,
                this._mediaKeyPQ,
                this._mediaKeyIndex,
            );

            this._sendSessionInitMessage(otKey, commitmentToKeys, pId);

            olmData.status = PROTOCOL_STATUS.WAITING_PQ_SESSION_INIT;
        } catch (e) {
            console.error(`E2E: sendSessionInit failed: ${e}`);
        }
    }
}

OlmAdapter.events = OlmAdapterEvents;
