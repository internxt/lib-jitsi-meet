import { safeJsonParse } from "@jitsi/js-utils/json";
import { getLogger } from "@jitsi/logger";
import * as base64js from "base64-js";
import { v4 as uuidv4 } from "uuid";

import * as JitsiConferenceEvents from "../../JitsiConferenceEvents";
import Listenable from "../util/Listenable";
import { FEATURE_E2EE, JITSI_MEET_MUC_TYPE } from "../xmpp/xmpp";

import {
    generateKyberKeys,
    encapsulateSecret,
    decapsulateAndDeriveOneKey,
    decryptKeyInfoPQ,
    encryptKeyInfoPQ,
    generateKey,
    ratchetKey,
    computeKeyCommitment
} from "./crypto-utils";
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
    SESSION_INIT: "session-init",
    PQ_SESSION_INIT: "pq-session-init",
};

const PROTOCOL_STATUS = {
    ERROR: "error",
    NOT_STARTED: "ready-to-start",
    WAITING_SESSION_ACK: "waiting-for-session-ack",
    WAITING_PQ_SESSION_ACK: "waiting-for-pq-session-ack",
    WAITING_PQ_SESSION_INIT: "waiting-for-pq-session-init",
    DONE: "sucessfully established",
};

const kOlmData = "OlmData";
const OlmAdapterEvents = {
    START_DECRYPTION: "olm.start_decryption",
    STOP_DECRYPTION: "olm.stop_decryption",
    PARTICIPANT_KEY_RATCHET: "olm.partitipant_key_ratchet",
    PARTICIPANT_KEY_UPDATED: "olm.partitipant_key_updated",
    PARTICIPANT_KEYS_COMMITMENT: "olm.participant_keys_commitment",
};

type IdentityKeys = {
    ed25519: string;
    curve25519: string;
};

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
        Uint8Array,
        { resolve: (args?: unknown) => void; reject?: (args?: unknown) => void }
    >;
    private _publicKeyBase64: string;
    private _privateKey: Uint8Array;
    private _olmAccount: Window["Olm"]["Account"];
    private _idKeys: IdentityKeys;
    static events: {
        START_DECRYPTION: string;
        STOP_DECRYPTION: string;
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
    constructor(conference) {
        super();
        this._conf = conference;
        this._mediaKeyOlm = undefined;
        this._mediaKeyPQ = undefined;
        this._mediaKeyIndex = -1;
        this._reqs = new Map();
        this._publicKeyBase64 = undefined;
        this._privateKey = undefined;

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

            this._idKeys = safeJsonParse(this._olmAccount.identity_keys());

            const { publicKeyBase64, privateKey } = await generateKyberKeys();
            this._publicKeyBase64 = publicKeyBase64;
            this._privateKey = privateKey;
            this._onIdKeysReady(this._idKeys);

            const commitment = await computeKeyCommitment(publicKeyBase64, this._idKeys.curve25519);
            this.emit(
                OlmAdapterEvents.PARTICIPANT_KEYS_COMMITMENT,
                this.myId,
                commitment,
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
        if (olmData.status === PROTOCOL_STATUS.DONE) {
            try {
                const uuid = uuidv4();
                const pqCiphertextBase64 = await encryptKeyInfoPQ(
                    olmData.pqSessionKey,
                    this._mediaKeyPQ,
                );
                const olmCiphertext = this._encryptKeyInfo(olmData.session_for_sending);
                logger.info(`E2E: Sending KEY_INFO to ${pId}`);
                this._sendKeyInfoMessage(
                    uuid,
                    olmCiphertext,
                    pqCiphertextBase64,
                    pId,
                );
            } catch (error) {
                this._sendError(
                    pId,
                    `Sending KEY_INFO failed for ${pId}: ${error}`,
                );
            }
        } else {
            this._sendStatusError(
                pId,
                olmData.status,
                OLM_MESSAGE_TYPES.KEY_INFO,
            );
        }
    }

    /**
     * Sends KEY_INFO message to all participants.
     *
     * @private
     */
    async sendKeyInfoToAll() {
        try {
            for (const participant of this._conf.getParticipants()) {
                await this.sendKeyInfoToParticipant(participant);
            }
        } catch (error) {
            logger.error(`E2E: Failed to send key info to all: ${error}`);
            throw new Error(`Failed to send key info to all: ${error}`);
        }
    }

    /**
     *  Ratcheting keys of the participant.
     *
     * @param {JitsiParticipant} participant
     * @returns {Promise<void>}  Resolves when PARTICIPANT_KEY_RATCHET is emitted.
     * @private
     */
    async ratchetParticipantKeys(participant: JitsiParticipant) {
        const pId = participant.getId();
        const olmData = this._getParticipantOlmData(participant);
        if (olmData.gotKeys) {
            this.emit(OlmAdapterEvents.PARTICIPANT_KEY_RATCHET, pId);
        }
    }

    /**
     * Rarchets keys of all participants.
     *
     * @private
     */
    async ratchetAllKeys() {
        try {
            for (const participant of this._conf.getParticipants()) {
                await this.ratchetParticipantKeys(participant);
            }
        } catch (error) {
            logger.error(`E2E: Failed to ratchet all keys: ${error}`);
            throw new Error(`E2E: Failed to racthet all keys: ${error}`);
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
                case "e2ee.idKey.ed25519": {
                    const olmData = this._getParticipantOlmData(participant);
                    olmData.ed25519 = newValue;
                    break;
                }
                case "e2ee.enabled":
                    if (newValue) {
                        logger.info(
                            `E2E: Participant ${participant.getId()} STARTED encrypting data.`,
                        );
                    } else {
                        logger.info(
                            `E2E: Participant ${participant.getId()} STOPPED encrypting data.`,
                        );
                    }
                    break;
            }
        }
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
            const localParticipantId = this._conf.myUserId();
            const participants = this._conf.getParticipants();
            logger.info(
                `E2E: List of all participants:  ${participants.map((p) => p.getId())}`,
            );
            const list = participants.filter(
                (participant) =>
                    participant.hasFeature(FEATURE_E2EE) &&
                    localParticipantId > participant.getId(),
            );
            logger.info(
                `E2E: My ID is ${localParticipantId}, should send session-init to everyone with smaller IDs: [ ${list.map((p) => p.getId())}]`,
            );
            const promises = list.map((participant) =>
                this._sendSessionInit(participant).catch((error) => {
                    logger.error(
                        `E2E: Failed to initialize session with ${participant.getId()}:`,
                        error,
                    );
                }),
            );

            const results = await Promise.allSettled(promises);
            results.forEach((result, index) => {
                if (result.status === "rejected") {
                    logger.error(
                        `E2E: Failed to initialize session with ${list[index].getId()}:`,
                        result.reason,
                    );
                } else {
                    logger.info(
                        `E2E: Session initialized successfully with ${list[index].getId()}`,
                    );
                }
            });
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
            await this.ratchetAllKeys();
        } catch (error) {
            logger.error(`E2E: Failed to ratchet keys: ${error}`);
            throw new Error(`Failed to ratchet keys: ${error}`);
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
            this.generateNewKeys();
            await this.sendKeyInfoToAll();
        } catch (error) {
            logger.error(`E2E: Failed to rotate my keys: ${error}`);
            throw new Error(`Failed to rotate my keys: ${error}`);
        }
    }

    /**
     * Returns current keys and index.
     *
     * @returns {Uint8Array, Uint8Array, number} A tuple containing the olm key, pq key, and the current index.
     * @private
     */
    getCurrentKeys(): { olmKey: Uint8Array; pqKey: Uint8Array; index: number } {
        return {
            olmKey: this._mediaKeyOlm,
            pqKey: this._mediaKeyPQ,
            index: this._mediaKeyIndex,
        };
    }

    /**
     * Generate new keys and advance the index.
     * @private
     */
    generateNewKeys() {
        this._mediaKeyOlm = generateKey();
        this._mediaKeyPQ = generateKey();
        this._mediaKeyIndex++;
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
            throw new Error(
                `Failed to clear session for participat ${participant.getId()}: ${error}`,
            );
        }
    }

    /**
     * Frees the olmData sessions for all participants.
     *
     * @private
     */
    clearAllParticipantsSessions() {
        try {
            for (const participant of this._conf.getParticipants()) {
                this.clearParticipantSession(participant);
            }
        } catch (error) {
            logger.error(`E2E: Failed to clear all sessions: ${error}`);
            throw new Error(`Failed to clear all sessions: ${error}`);
        }
    }

    /**
     * Publishes our own Olmn id key in presence.
     * @private
     */
    _onIdKeysReady(idKeys) {
        // Publish it in presence.
        for (const keyType in idKeys) {
            if (Object.prototype.hasOwnProperty.call(idKeys, keyType)) {
                const key = idKeys[keyType];

                this._conf.setLocalParticipantProperty(
                    `e2ee.idKey.${keyType}`,
                    key,
                );
            }
        }
    }

    /**
     * Internal helper for encrypting the current key information for a given participant.
     *
     * @param {Olm.Session} session - Participant's session.
     * @returns {string} - The encrypted text with the key information.
     * @private
     */
    _encryptKeyInfo(session) {
        const encryptionKey = this._mediaKeyOlm
            ? base64js.fromByteArray(this._mediaKeyOlm)
            : undefined;
        const index = this._mediaKeyOlm ? this._mediaKeyIndex : -1;

        return session.encrypt(JSON.stringify({ encryptionKey, index }));
    }

    _decryptKeyInfo(session, encKey) {
        const data = session.decrypt(encKey.type, encKey.body);
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
    _getParticipantOlmData(participant: JitsiParticipant) {
        participant[kOlmData] = participant[kOlmData] || {};
        const data = participant[kOlmData];
        if (!data.status) {
            data.status = PROTOCOL_STATUS.NOT_STARTED;
        }
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
        uuid: string,
        idKey: string,
        otKey: string,
        publicKyberKey: string,
        pId: string,
    ): Promise<void> {
        const init = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.SESSION_INIT,
                data: {
                    idKey,
                    otKey,
                    publicKyberKey,
                    uuid,
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
        uuid: string,
        ciphertext: string,
        publicKyberKey: string,
        encapsKyber: string,
        idKey: string,
        otKey: string,
        pId: string,
    ): Promise<void> {
        const ack = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.PQ_SESSION_INIT,
                data: {
                    uuid,
                    publicKyberKey,
                    ciphertext,
                    encapsKyber,
                    idKey,
                    otKey,
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
        uuid: string,
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
                    uuid,
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
        uuid: string,
        pqEncKey: string,
        pId: string,
    ): Promise<void> {
        const ack = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.SESSION_ACK,
                data: {
                    pqEncKey,
                    uuid,
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
        uuid: string,
        ciphertext: string,
        pqCiphertext: string,
        pId: string,
    ): Promise<void> {
        const info = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.KEY_INFO,
                data: {
                    ciphertext,
                    pqCiphertext,
                    uuid,
                },
            },
        };
        this._sendMessage(info, pId);
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
            const uuid = msg.data.uuid;
            const olmData = this._getParticipantOlmData(participant);

            switch (msg.type) {
                case OLM_MESSAGE_TYPES.SESSION_INIT: {
                    if (olmData.status === PROTOCOL_STATUS.NOT_STARTED) {
                        const { publicKyberKey, idKey, otKey } = msg.data;

                        const commitment = await computeKeyCommitment(publicKyberKey, idKey);
                        this.emit(
                            OlmAdapterEvents.PARTICIPANT_KEYS_COMMITMENT,
                            pId,
                            commitment,
                        );

                        const session_outbound = new window.Olm.Session();
                        session_outbound.create_outbound(this._olmAccount, idKey, otKey);
                        olmData.session_for_sending = session_outbound;

                        const { encapsulatedBase64, sharedSecret } =
                            await encapsulateSecret(publicKyberKey);
                        olmData._kemSecret = sharedSecret;

                        const olmEncKey = this._encryptKeyInfo(session_outbound);

                        const myOtKey = this._getOneTimeKey(this._olmAccount);


                        this._sendPQSessionInitMessage(
                            uuid,
                            olmEncKey,
                            this._publicKeyBase64,
                            encapsulatedBase64,
                            this._idKeys.curve25519,
                            myOtKey,
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
                        const { publicKyberKey, ciphertext, encapsKyber, idKey, otKey } =
                            msg.data;

                        const commitment = await computeKeyCommitment(publicKyberKey, idKey);
                        this.emit(
                            OlmAdapterEvents.PARTICIPANT_KEYS_COMMITMENT,
                            pId,
                            commitment,
                        );

                        const { encapsulatedBase64, sharedSecret } =
                            await encapsulateSecret(publicKyberKey);

                        olmData.pqSessionKey = await decapsulateAndDeriveOneKey(
                            encapsKyber,
                            this._privateKey,
                            sharedSecret,
                            true,
                        );

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
                        olmData.newKey = key;
                        olmData.newIndex = index;

                        const pqCiphertextBase64 = await encryptKeyInfoPQ(
                            olmData.pqSessionKey,
                            this._mediaKeyPQ,
                        );

                        const session_outbound = new window.Olm.Session();
                        session_outbound.create_outbound(this._olmAccount, idKey, otKey);
                        olmData.session_for_sending = session_outbound;

                        const olmCiphertext = this._encryptKeyInfo(
                            olmData.session_for_sending,
                        );

                        logger.info(`E2E: Sent my keys to ${pId}.`);
                        this._sendPQSessionAckMessage(
                            uuid,
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
                        const { ciphertext, pqCiphertext, encapsKyber } =
                            msg.data;

                        olmData.pqSessionKey = await decapsulateAndDeriveOneKey(
                            encapsKyber,
                            this._privateKey,
                            olmData._kemSecret,
                            false,
                        );

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

                        logger.info(`E2E: Recived new keys from ${pId}`);
                        this.emit(
                            OlmAdapterEvents.PARTICIPANT_KEY_UPDATED,
                            pId,
                            key,
                            pqKey,
                            index,
                        );
                        olmData.gotKeys = true;

                        const pqCiphertextBase64 = await encryptKeyInfoPQ(
                            olmData.pqSessionKey,
                            this._mediaKeyPQ,
                        );
                        logger.info(`E2E: Sent my keys to ${pId}.`);
                        this._sendSessionAckMessage(
                            uuid,
                            pqCiphertextBase64,
                            pId,
                        );

                        olmData.status = PROTOCOL_STATUS.DONE;
                        logger.info(
                            `E2E: Participant ${pId} established E2E channel with us.`,
                        );
                    } else this._sendStatusError(pId, msg.type, olmData.status);
                    break;
                }
                case OLM_MESSAGE_TYPES.SESSION_ACK: {
                    if (
                        olmData.status === PROTOCOL_STATUS.WAITING_SESSION_ACK
                    ) {
                        const { pqEncKey } = msg.data;

                        const pqKey = await decryptKeyInfoPQ(
                            pqEncKey,
                            olmData.pqSessionKey,
                        );

                        logger.info(`E2E: Recived new keys from ${pId}`);
                        this.emit(
                            OlmAdapterEvents.PARTICIPANT_KEY_UPDATED,
                            pId,
                            olmData.newKey,
                            pqKey,
                            olmData.newIndex,
                        );
                        olmData.gotKeys = true;
                        olmData.status = PROTOCOL_STATUS.DONE;

                        const requestPromise = this._reqs.get(uuid);
                        if (requestPromise) {
                            requestPromise.resolve();
                            this._reqs.delete(uuid);
                        } else
                            logger.warn(
                                `E2E: Session with ${pId} was established after reaching time out.`,
                            );
                    } else this._sendStatusError(pId, msg.type, olmData.status);
                    break;
                }
                case OLM_MESSAGE_TYPES.ERROR: {
                    this._sendError(pId, msg.data.error);
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

                        logger.info(
                            `E2E: sending my keys to participant ${pId}`,
                        );
                        this.emit(
                            OlmAdapterEvents.PARTICIPANT_KEY_UPDATED,
                            pId,
                            key,
                            pqKey,
                            index,
                        );
                    } else this._sendStatusError(pId, msg.type, olmData.status);
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
     * Handles a participant leaving. When a participant leaves their olm session is destroyed.
     *
     * @private
     */
    _onParticipantLeft(id, participant: JitsiParticipant) {
        logger.info(`E2E: Participant ${id} left`);
        this.clearParticipantSession(participant);
    }

    /**
     * Builds and sends an error message to the target participant.
     *
     * @param {string} id - The target participant.
     * @param {string} error - The error message.
     * @returns {void}
     */
    _sendError(pId: string, error) {
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
    _sendMessage(data, participantId) {
        this._conf.sendMessage(data, participantId);
    }

    _getOneTimeKey(olmAccount): string {

        // Generate a One Time Key.
        olmAccount.generate_one_time_keys(1);

        const otKeys = safeJsonParse(olmAccount.one_time_keys());
        const values = Object.values(otKeys.curve25519);

        if (!values.length || typeof values[0] !== "string") {
            throw new Error("E2E: No one-time-keys generated");
        }

        const otKey: string = values[0];

        // Mark the OT keys (one really) as published so they are not reused.
        olmAccount.mark_keys_as_published();

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
            if (olmData.status === PROTOCOL_STATUS.DONE) return;

            const pId = participant.getId();
            if (olmData.status === PROTOCOL_STATUS.NOT_STARTED) {
                logger.info(`E2E: Sending session init to participant ${pId} `);

                const otKey = this._getOneTimeKey(this._olmAccount);

                const uuid = uuidv4();

                const sessionPromise = new Promise((resolve, reject) => {
                    this._reqs.set(uuid, { resolve, reject });
                });

                const timeoutPromise = new Promise((_, reject) =>
                    setTimeout(
                        () =>
                            reject(
                                new Error(
                                    "E2E: Session init request timed out",
                                ),
                            ),
                        REQ_TIMEOUT,
                    ),
                );

                this._sendSessionInitMessage(
                    uuid,
                    this._idKeys.curve25519,
                    otKey,
                    this._publicKeyBase64,
                    pId,
                );

                olmData.status = PROTOCOL_STATUS.WAITING_PQ_SESSION_INIT;

                // Simulates timeout with deferred object but using promises
                return Promise.race([sessionPromise, timeoutPromise]).catch(
                    (error) => {
                        this._reqs.delete(uuid);
                        throw error;
                    },
                );
            } else {
                this._sendError(
                    pId,
                    `Trying (${this.myId}) to send SESSION_INIT to ${pId} but status is ${olmData.status}`,
                );
            }
        } catch (e) {
            this._sendError(
                participant.getId(),
                `sendSessionInit failed for ${participant.getId()}: ${e}`,
            );
        }
    }
}

OlmAdapter.events = OlmAdapterEvents;
