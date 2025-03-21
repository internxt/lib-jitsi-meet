import { safeJsonParse } from "@jitsi/js-utils/json";
import { getLogger } from "@jitsi/logger";
import * as base64js from "base64-js";

import * as JitsiConferenceEvents from "../../JitsiConferenceEvents";
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
} from "./crypto-workers";
import JitsiConference from "../../JitsiConference";
import JitsiParticipant from "../../JitsiParticipant";

const logger = getLogger(__filename);

const REQ_TIMEOUT = 20 * 1000;
const OLM_MESSAGE_TYPE = "olm";
const OLM_MESSAGE_TYPES = {
    ERROR: "error",
    KEY_INFO: "key-info",
    SESSION_ACK: "session-ack",
    PQ_SESSION_ACK: "pq-session-ack",
    RATCHET_INFO: "ratchet-info",
    SESSION_INIT: "session-init",
    PQ_SESSION_INIT: "pq-session-init",   
};

const PROTOCOL_STATUS = {
    NOT_STARTED: "ready-to-start",
    WAITING_SESSION_ACK: "waiting-for-session-ack",
    WAITING_PQ_SESSION_ACK: "waiting-for-pq-session-ack",
    WAITING_PQ_SESSION_INIT: "waiting-for-pq-session-init",
    DONE: "sucessfully established",
};
type ProtocolStatus = (typeof PROTOCOL_STATUS)[keyof typeof PROTOCOL_STATUS];
type OlmSession = Window["Olm"]["Session"];
type OlmAccount = Window["Olm"]["Account"];

const kOlmData = "OlmData";
const OlmAdapterEvents = {
    PARTICIPANT_KEY_RATCHET: "olm.participan_ratcheted_keys",
    PARTICIPANT_KEY_UPDATED: "olm.participan_updated_keys",
    PARTICIPANT_KEYS_COMMITMENT: "olm.participant_keys_committed",
};

class OlmData {
    status: ProtocolStatus;
    commitmentToMediaKeys: string;
    keyToSendOlm: Uint8Array;
    keyToSendPQ: Uint8Array;
    indexToSend: number;
    ratchetCount: number;
    session_for_sending: OlmSession;
    session_for_reciving: OlmSession;
    pqSessionKey: CryptoKey;
    kemSecret: Uint8Array;
    constructor() {
        this.status = PROTOCOL_STATUS.NOT_STARTED;
        this.commitmentToMediaKeys = "";
        this.session_for_sending = null as any;
        this.session_for_reciving = null as any;
        this.pqSessionKey = null as any;
        this.kemSecret = new Uint8Array();
        this.keyToSendOlm = new Uint8Array();
        this.keyToSendPQ = new Uint8Array();
        this.ratchetCount = 0;
        this.indexToSend = -1;
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
    private _olmWasInitialized: Promise<boolean>;
    private _mediaKeyOlm: Uint8Array;
    private _mediaKeyPQ: Uint8Array;
    private _mediaKeyIndex: number;
    private _reqs: Map<
        string,
        { resolve: (args?: unknown) => void; reject?: (args?: unknown) => void }
    >;
    private _publicKyberKeyBase64: string;
    private _privateKyberKey: Uint8Array;
    private _olmAccount: OlmAccount;
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

        if (OlmAdapter.isSupported()) {
            this._olmWasInitialized = this._bootstrapOlm();
            this._conf.on(
                JitsiConferenceEvents.ENDPOINT_MESSAGE_RECEIVED,
                this._onEndpointMessageReceived.bind(this),
            );
            this._conf.on(
                JitsiConferenceEvents.CONFERENCE_LEFT,
                this._onConferenceLeft.bind(this),
            );
            this._conf.on(
                JitsiConferenceEvents.USER_LEFT,
                this._onParticipantLeft.bind(this),
            );
            this._conf.on(
                JitsiConferenceEvents.PARTICIPANT_PROPERTY_CHANGED,
                this._onParticipantPropertyChanged.bind(this),
            );
        } else {
            this._olmWasInitialized = Promise.reject(false);
        }
    }

    /**
     * Initializes the Olm library and sets up the account.
     * This includes setting up cryptographic keys.
     *
     * @returns {Promise<boolean>}  Returns true when initialization is complete.
     * @private
     */
    async _bootstrapOlm(): Promise<boolean> {
        if (!OlmAdapter.isSupported()) {
            return false;
        }

        try {
            await window.Olm.init();

            this._olmAccount = new window.Olm.Account();
            this._olmAccount.create();

            const idKeys = safeJsonParse(this._olmAccount.identity_keys());
            this._publicCurve25519Key = idKeys.curve25519;

            const { publicKeyBase64, privateKey } = await generateKyberKeys();
            this._publicKyberKeyBase64 = publicKeyBase64;
            this._privateKyberKey = privateKey;
            this._indenityKeyCommitment = await computeCommitment(
                this._publicKyberKeyBase64,
                this._publicCurve25519Key,
            );
            return true;
        } catch (error) {
            logger.error("E2E: Failed to initialize Olm", error);
            return false;
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

    async _commitToSecret(
        id: string,
        keyOlm: Uint8Array,
        keyPQ: Uint8Array,
        index: number,
    ) {
        const com1 = await computeCommitment(id + index, keyOlm);
        const com2 = await computeCommitment(id + index, keyPQ);
        return com1 + com2;
    }

    /**
     * Sends KEY_INFO message to the participant.
     *
     * @param {JitsiParticipant} participant
     * @returns {Promise<void>}  Resolves when KEY_INFO message is sent.
     * @private
     */
    async sendKeyInfoToParticipant(participant: JitsiParticipant) {
        const pId = participant.getId();
        const olmData = this._getParticipantOlmData(participant);
        if (olmData.session_for_sending && olmData.pqSessionKey) {
            try {
                const pqCiphertext = await encryptKeyInfoPQ(
                    olmData.pqSessionKey,
                    this._mediaKeyPQ,
                );
                const ciphertext = this._encryptKeyInfo(
                    olmData.session_for_sending,
                    this._mediaKeyOlm,
                    this._mediaKeyIndex,
                );

                const info = {
                    [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
                    olm: {
                        type: OLM_MESSAGE_TYPES.KEY_INFO,
                        data: {
                            ciphertext,
                            pqCiphertext,
                        },
                    },
                };
                logger.info(`E2E: Sending KEY_INFO to the participant ${pId}`);
                this._sendMessage(info, pId);
            } catch (error) {
                this._sendError(
                    pId,
                    `Sending KEY_INFO failed for participant ${pId}: ${error}`,
                );
            }
        }
    }

      /**
     * Handles an update in a participant's presence property.
     *
     * @param {JitsiParticipant} participant - The participant.
     * @param {string} name - The name of the property that changed.
     * @param {*} oldValue - The property's previous value.
     * @param {*} newValue - The property's new value.
     * @private
     */
      async _onParticipantPropertyChanged(
        participant: JitsiParticipant,
        name: string,
        oldValue,
        newValue,
    ) {
        if (newValue !== oldValue) {
            switch (name) {
                case "e2ee.enabled":
                    if (newValue) {
                        console.log(
                            `E2E: Participant ${participant.getId()} STARTED encrypting data.`,
                        );
                    } else {
                        console.log(
                            `E2E: Participant ${participant.getId()} STOPPED encrypting data.`,
                        );
                    }
                    break;
            }
        }
    }

    /**
     * Sends KEY_INFO message to the participant.
     *
     * @param {string} pId
     * @returns {void}  Resolves when KEY_INFO message is sent.
     * @private
     */
    sendRatchetInfoToParticipant(pId: string) {
        const info = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.RATCHET_INFO,
                data: {
                    index: this._mediaKeyIndex,
                },
            },
        };
        logger.info(`E2E: Sending RATCHET_INFO to the participant ${pId}`);
        this._sendMessage(info, pId);
    }

    /**
     * Starts new olm sessions with every other participant that has the participantId "smaller" the localParticipantId.
     *
     * @private
     */
    async initSessions() {
        if (!(await this._olmWasInitialized)) {
            throw new Error(
                "E2E: Cannot init sessions because olm was not initialized",
            );
        }
        try {
            const localParticipantId = this.myId;
            this._onKeysCommitment(localParticipantId, this._indenityKeyCommitment);
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
            logger.info(
                `E2E: My ID is ${localParticipantId}, should send session-init to everyone with smaller IDs: [ ${list.map((p) => p.getId())}]`,
            );
            const promises = list.map((participant) => {
                this._sendSessionInit(participant);

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
                        logger.info(
                            `E2E: Session with ${pId} initialized successfully.`,
                        );
                        return result;
                    })
                    .catch((error) => {
                        this._reqs.delete(pId);
                        logger.error(
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
     * Indicates if olm is supported on the current platform.
     *
     * @returns {boolean}
     */
    static isSupported() {
        return typeof window.Olm !== "undefined";
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
            logger.info(
                `E2E: Ratcheted my keys, new index = ${this._mediaKeyIndex}`,
            );
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

                if (status == PROTOCOL_STATUS.DONE) {
                    this.emit(OlmAdapterEvents.PARTICIPANT_KEY_RATCHET, pId);
                }

                if (
                    status != PROTOCOL_STATUS.DONE &&
                    status != PROTOCOL_STATUS.NOT_STARTED
                ) {
                    logger.info(
                        `E2E: Sending RATCHET_INFO to ${pId}, status= ${olmData.status}, sendIndex = ${olmData.indexToSend}`,
                    );
                    await this.sendRatchetInfoToParticipant(pId);
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
            logger.info("E2E: Rotating my keys");
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
                await this.sendKeyInfoToParticipant(participant);
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

            if (olmData.session_for_sending) {
                olmData.session_for_sending.free();
                olmData.session_for_sending = undefined;
            }
            if (olmData.session_for_reciving) {
                olmData.session_for_reciving.free();
                olmData.session_for_reciving = undefined;
            }
            olmData.status = PROTOCOL_STATUS.NOT_STARTED;
        } catch (error) {
            logger.error(
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
    async _onKeysCommitment(
        pId: string,
        commitment: string,
    ) {
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
     * Internal helper for encrypting the current key information for a given participant.
     *
     * @param {Olm.Session} session - Participant's session.
     * @returns {string} - The encrypted text with the key information.
     * @private
     */
    _encryptKeyInfo(session: OlmSession, key: Uint8Array, index: number) {
        const encryptionKey = base64js.fromByteArray(key);
        return session.encrypt(JSON.stringify({ encryptionKey, index }));
    }

    _decryptKeyInfo(session: OlmSession, ciphertext) {
        const data = session.decrypt(ciphertext.type, ciphertext.body);
        const json = safeJsonParse(data);
        const key = base64js.toByteArray(json.encryptionKey);
        return { key: key, index: json.index };
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
        if (await this._olmWasInitialized) {
            for (const participant of this._conf.getParticipants()) {
                this._onParticipantLeft(participant.getId(), participant);
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
        publicKey: string,
        publicKyberKey: string,
        commitment: string,
        pId: string,
    ): Promise<void> {
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

    /**
     * Sends PQ_SESSION_INIT message
     *
     * @private
     */
    async _sendPQSessionInitMessage(
        encapsKyber: string,
        otKey: string,
        publicKey: string,
        publicKyberKey: string,
        commitment: string,
        pId: string,
    ): Promise<void> {
        const ack = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.PQ_SESSION_INIT,
                data: {
                    encapsKyber,
                    otKey,
                    publicKey,
                    publicKyberKey,
                    commitment,
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
        ciphertext: string,
        pqCiphertext: string,
        pId: string,
    ): Promise<void> {
        const ack = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.PQ_SESSION_ACK,
                data: {
                    encapsKyber,
                    ciphertext,
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
        ciphertext: string,
        pqCiphertext: string,
        pId: string,
    ): Promise<void> {
        const ack = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.SESSION_ACK,
                data: {
                    ciphertext,
                    pqCiphertext,
                },
            },
        };

        this._sendMessage(ack, pId);
    }

    /**
     * Main message handler. Handles 1-to-1 messages received from other participants
     * and send the appropriate replies.
     *
     * @private
     */
    async _onEndpointMessageReceived(participant: JitsiParticipant, payload) {
        if (payload[JITSI_MEET_MUC_TYPE] !== OLM_MESSAGE_TYPE) {
            return;
        }

        if (!payload.olm) {
            logger.warn(
                "E2E: _onEndpointMessageReceived: Incorrectly formatted message: ",
            );

            return;
        }

        if (!(await this._olmWasInitialized)) {
            throw new Error("Olm not initialized");
        }

        const msg = payload.olm;
        const pId = participant.getId();

        try {
            const olmData = this._getParticipantOlmData(participant);

            switch (msg.type) {
                case OLM_MESSAGE_TYPES.SESSION_INIT: {
                    if (olmData.status === PROTOCOL_STATUS.NOT_STARTED) {
                        const { otKey, publicKey, publicKyberKey, commitment } =
                            msg.data;
                        olmData.commitmentToMediaKeys = commitment;
                        const keyCommitment = await computeCommitment(publicKyberKey, publicKey);
                        this._onKeysCommitment(pId, keyCommitment);

                        const session_outbound = new window.Olm.Session();
                        session_outbound.create_outbound(
                            this._olmAccount,
                            publicKey,
                            otKey,
                        );
                        olmData.session_for_sending = session_outbound;

                        const { encapsulatedBase64, sharedSecret } =
                            await encapsulateSecret(publicKyberKey);
                        olmData.kemSecret = sharedSecret;

                        const myOtKey = this._getOneTimeKey();

                        olmData.keyToSendPQ = this._mediaKeyPQ;
                        olmData.keyToSendOlm = this._mediaKeyOlm;
                        olmData.indexToSend = this._mediaKeyIndex;
                        const commitmentToMediaKeys =
                            await this._commitToSecret(
                                this.myId,
                                olmData.keyToSendOlm,
                                olmData.keyToSendPQ,
                                olmData.indexToSend,
                            );

                        this._sendPQSessionInitMessage(
                            encapsulatedBase64,
                            myOtKey,
                            this._publicCurve25519Key,
                            this._publicKyberKeyBase64,
                            commitmentToMediaKeys,
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
                            otKey,
                            publicKey,
                            publicKyberKey,
                            commitment,
                        } = msg.data;

                        olmData.commitmentToMediaKeys = commitment;
                        const keyCommitment = await computeCommitment(publicKyberKey, publicKey);
                        this._onKeysCommitment(pId, keyCommitment);

                        const session_outbound = new window.Olm.Session();
                        session_outbound.create_outbound(
                            this._olmAccount,
                            publicKey,
                            otKey,
                        );
                        olmData.session_for_sending = session_outbound;

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

                        const pqCiphertextBase64 = await encryptKeyInfoPQ(
                            olmData.pqSessionKey,
                            olmData.keyToSendPQ,
                        );

                        const olmCiphertext = this._encryptKeyInfo(
                            olmData.session_for_sending,
                            olmData.keyToSendOlm,
                            olmData.indexToSend,
                        );
                        olmData.keyToSendOlm = new Uint8Array();
                        olmData.keyToSendPQ = new Uint8Array();
                        olmData.indexToSend = -1;

                        this._sendPQSessionAckMessage(
                            encapsulatedBase64,
                            olmCiphertext,
                            pqCiphertextBase64,
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
                        const { encapsKyber, ciphertext, pqCiphertext } =
                            msg.data;

                        const session_inbound = new window.Olm.Session();
                        session_inbound.create_inbound(
                            this._olmAccount,
                            ciphertext.body,
                        );
                        this._olmAccount.remove_one_time_keys(session_inbound);
                        olmData.session_for_reciving = session_inbound;

                        const decapsulatedSecret = await decapsulateSecret(
                            encapsKyber,
                            this._privateKyberKey,
                        );

                        olmData.pqSessionKey = await deriveEncryptionKey(
                            olmData.kemSecret,
                            decapsulatedSecret,
                        );

                        const { key, index } = this._decryptKeyInfo(
                            olmData.session_for_reciving,
                            ciphertext,
                        );

                        const pqKey = await decryptKeyInfoPQ(
                            pqCiphertext,
                            olmData.pqSessionKey,
                        );

                        const commitment = await this._commitToSecret(
                            pId,
                            key,
                            pqKey,
                            index,
                        );

                        if (olmData.commitmentToMediaKeys != commitment)
                            this._sendError(
                                pId,
                                `Keys do not match the commitment.`,
                            );
                        else {
                            logger.info(`E2E: Recived new keys from ${pId}`);
                            await this._setParticipantKeys(
                                pId,
                                key,
                                pqKey,
                                index,
                                olmData.ratchetCount,
                            );
                            olmData.ratchetCount = 0;

                            const olmCiphertext = this._encryptKeyInfo(
                                olmData.session_for_sending,
                                olmData.keyToSendOlm,
                                olmData.indexToSend,
                            );

                            const pqCiphertextBase64 = await encryptKeyInfoPQ(
                                olmData.pqSessionKey,
                                olmData.keyToSendPQ,
                            );
                            olmData.keyToSendPQ = new Uint8Array();
                            olmData.keyToSendOlm = new Uint8Array();
                            olmData.indexToSend = -1;
                            logger.info(
                                `E2E: Sent my keys to ${pId}, index = ${this._mediaKeyIndex}.`,
                            );
                            this._sendSessionAckMessage(
                                olmCiphertext,
                                pqCiphertextBase64,
                                pId,
                            );

                            olmData.status = PROTOCOL_STATUS.DONE;
                            logger.info(
                                `E2E: Participant ${pId} established E2E channel with us.`,
                            );
                        }
                    } else this._sendStatusError(pId, msg.type, olmData.status);
                    break;
                }
                case OLM_MESSAGE_TYPES.SESSION_ACK: {
                    if (
                        olmData.status === PROTOCOL_STATUS.WAITING_SESSION_ACK
                    ) {
                        const { ciphertext, pqCiphertext } = msg.data;

                        const session_inbound = new window.Olm.Session();
                        session_inbound.create_inbound(
                            this._olmAccount,
                            ciphertext.body,
                        );
                        this._olmAccount.remove_one_time_keys(session_inbound);
                        olmData.session_for_reciving = session_inbound;

                        const { key, index } = this._decryptKeyInfo(
                            olmData.session_for_reciving,
                            ciphertext,
                        );

                        const pqKey = await decryptKeyInfoPQ(
                            pqCiphertext,
                            olmData.pqSessionKey,
                        );
                        const commitment = await this._commitToSecret(
                            pId,
                            key,
                            pqKey,
                            index,
                        );

                        if (olmData.commitmentToMediaKeys != commitment) {
                            this._sendError(
                                pId,
                                `Keys do not match the commitment.`,
                            );
                            logger.warn(`E2E: Rotating my keys.`);
                            await this._rotateKeyImpl();
                        } else {
                            logger.info(`E2E: Recived new keys from ${pId}`);
                            await this._setParticipantKeys(
                                pId,
                                key,
                                pqKey,
                                index,
                                olmData.ratchetCount,
                            );
                            olmData.ratchetCount = 0;
                            olmData.status = PROTOCOL_STATUS.DONE;

                            const requestPromise = this._reqs.get(pId);
                            if (requestPromise) {
                                requestPromise.resolve();
                                this._reqs.delete(pId);
                            } else
                                logger.warn(
                                    `E2E: Session with ${pId} was established after reaching time out.`,
                                );
                        }
                    } else this._sendStatusError(pId, msg.type, olmData.status);
                    break;
                }
                case OLM_MESSAGE_TYPES.ERROR: {
                    logger.error(msg.data.error);
                    break;
                }
                case OLM_MESSAGE_TYPES.KEY_INFO: {
                    if (olmData.status === PROTOCOL_STATUS.DONE) {
                        const { ciphertext, pqCiphertext } = msg.data;
                        const { key, index } = this._decryptKeyInfo(
                            olmData.session_for_reciving,
                            ciphertext,
                        );
                        const pqKey = await decryptKeyInfoPQ(
                            pqCiphertext,
                            olmData.pqSessionKey,
                        );
                        this._onKeysUpdated(pId, key, pqKey, index);
                    } else {
                        console.warn(
                            `E2E: KEY_INFO from ${pId} arrived before session is established, re-sending`,
                        );
                        this._sendMessage(msg, this.myId);
                    }
                    break;
                }
                case OLM_MESSAGE_TYPES.RATCHET_INFO: {
                    if (olmData.session_for_reciving && olmData.pqSessionKey) {
                        this.emit(
                            OlmAdapterEvents.PARTICIPANT_KEY_RATCHET,
                            pId,
                        );
                    } else {
                        logger.info(
                            `E2E: RATCHET_INFO from ${pId} arrived before session is established`,
                        );
                        olmData.ratchetCount += 1;
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

    async _setParticipantKeys(
        pId: string,
        key: Uint8Array,
        pqKey: Uint8Array,
        index: number,
        ratchetCount: number,
    ) {
        this._onKeysUpdated(pId, key, pqKey, index);
        if (ratchetCount != 0) {
            let currentKey = key;
            let currentPqKey = pqKey;
            let currentIndex = index;
            while (ratchetCount > 0) {
                console.log(
                    `E2E: Ratchet keys of ${pId}, because they were updated duing session establishement`,
                );
                const newKey = await ratchetKey(currentKey);
                const newPqKey = await ratchetKey(currentPqKey);
                const newIndex = currentIndex + 1;
                this._onKeysUpdated(pId, newKey, newPqKey, newIndex);
                ratchetCount -= 1;
                currentKey = newKey;
                currentPqKey = newPqKey;
                currentIndex = newIndex;
            }
        }
    }
    /**
     * Handles a participant leaving. When a participant leaves their olm session is destroyed.
     *
     * @private
     */
    _onParticipantLeft(id: string, participant: JitsiParticipant) {
        this.clearParticipantSession(participant);
    }

    /**
     * Builds and sends an error message to the target participant.
     *
     * @param {string} id - The target participant.
     * @param {string} error - The error message.
     * @returns {void}
     */
    _sendError(pId: string, error: string) {
        logger.error(`E2E: ${error}`);
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

    _getOneTimeKey(): string {
        // Generate a One Time Key.
        this._olmAccount.generate_one_time_keys(1);

        const otKeys = safeJsonParse(this._olmAccount.one_time_keys());
        const values = Object.values(otKeys.curve25519);

        if (!values.length || typeof values[0] !== "string") {
            throw new Error("E2E: No one-time-keys generated");
        }

        const otKey: string = values[0];

        // Mark the OT keys (one really) as published so they are not reused.
        this._olmAccount.mark_keys_as_published();

        return otKey;
    }

    /**
     * Builds and sends the session-init request to the target participant.
     *
     * @param {JitsiParticipant} participant - Participant to whom we'll send the request.
     * @returns {Promise} - The promise will be resolved when the session-ack is received.
     * @private
     */
    async _sendSessionInit(participant: JitsiParticipant) {
        try {
            const olmData = this._getParticipantOlmData(participant);
            const pId = participant.getId();
            logger.info(`E2E: Sending session-init to participant ${pId} `);

            const otKey = this._getOneTimeKey();
            olmData.keyToSendPQ = this._mediaKeyPQ;
            olmData.keyToSendOlm = this._mediaKeyOlm;
            olmData.indexToSend = this._mediaKeyIndex;
            const secretCommitment = await this._commitToSecret(
                this.myId,
                olmData.keyToSendOlm,
                olmData.keyToSendPQ,
                olmData.indexToSend,
            );

            this._sendSessionInitMessage(
                otKey,
                this._publicCurve25519Key,
                this._publicKyberKeyBase64,
                secretCommitment,
                pId,
            );

            olmData.status = PROTOCOL_STATUS.WAITING_PQ_SESSION_INIT;
        } catch (e) {
            this._sendError(
                participant.getId(),
                `sendSessionInit failed for ${participant.getId()}: ${e}`,
            );
        }
    }
}

OlmAdapter.events = OlmAdapterEvents;
