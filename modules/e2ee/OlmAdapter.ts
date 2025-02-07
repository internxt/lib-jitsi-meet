import { safeJsonParse as _safeJsonParse } from "@jitsi/js-utils/json";
import { getLogger } from "@jitsi/logger";
import base64js from "base64-js";
import { isEqual } from "lodash-es";
import { v4 as uuidv4 } from "uuid";

import * as JitsiConferenceEvents from "../../JitsiConferenceEvents";
import Listenable from "../util/Listenable";
import { FEATURE_E2EE, JITSI_MEET_MUC_TYPE } from "../xmpp/xmpp";

import { E2EEErrors } from "./E2EEErrors";
import { generateSas } from "./SAS";
import {
    generateKyberKeys,
    encapsulateSecret,
    decapsulateAndDeriveOneKey,
    decryptKeyInfoPQ,
    encryptKeyInfoPQ,
} from "./crypto-utils";
import { KeyInfo } from "./KeyHandler";
import JitsiConference from "../../JitsiConference";
import JitsiParticipant from "../../JitsiParticipant";

const logger = getLogger(__filename);

const REQ_TIMEOUT = 8 * 1000;
const OLM_MESSAGE_TYPE = "olm";
const OLM_MESSAGE_TYPES = {
    ERROR: "error",
    KEY_INFO: "key-info",
    KEY_INFO_ACK: "key-info-ack",
    SESSION_ACK: "session-ack",
    PQ_SESSION_ACK: "pq-session-ack",
    SESSION_INIT: "session-init",
    PQ_SESSION_INIT: "pq-session-init",
    SAS_START: "sas-start",
    SAS_ACCEPT: "sas-accept",
    SAS_KEY: "sas-key",
    SAS_MAC: "sas-mac",
};

const PROTOCOL_STATUS = {
    ERROR: "error",
    NOT_STARTED: "ready-to-start",
    WAITING_SESSION_ACK: "waiting-for-session-ack",
    WAITING_PQ_SESSION_ACK: "waiting-for-pq-session-ack",
    WAITING_PQ_SESSION_INIT: "waiting-for-pq-session-init",
    DONE: "sucessfully established",
};

const OLM_SAS_NUM_BYTES = 6;
const OLM_KEY_VERIFICATION_MAC_INFO = "Jitsi-KEY_VERIFICATION_MAC";
const OLM_KEY_VERIFICATION_MAC_KEY_IDS = "Jitsi-KEY_IDS";

const kOlmData = "OlmData";
const OlmAdapterEvents = {
    PARTICIPANT_E2EE_CHANNEL_READY: "olm.participant_e2ee_channel_ready",
    PARTICIPANT_SAS_AVAILABLE: "olm.participant_sas_available",
    PARTICIPANT_SAS_READY: "olm.participant_sas_ready",
    PARTICIPANT_KEY_UPDATED: "olm.partitipant_key_updated",
    PARTICIPANT_VERIFICATION_COMPLETED:
        "olm.participant_verification_completed",
    GENERATE_KEYS: "olm.generate_keys",
};

/**
 * This class implements an End-to-End Encrypted communication channel between every two peers
 * in the conference. This channel uses libolm to achieve E2EE.
 *
 * The created channel is then used to exchange the secret key that each participant will use
 * to encrypt the actual media (see {@link E2EEContext}).
 *
 * A simple JSON message based protocol is implemented, which follows a request - response model:
 * - session-init: Initiates an olm session establishment procedure. This message will be sent
 *                 by the participant who just joined, to everyone else.
 * - session-ack: Completes the olm session etablishment. This messsage may contain ancilliary
 *                encrypted data, more specifically the sender's current key.
 * - key-info: Includes the sender's most up to date key information.
 * - key-info-ack: Acknowledges the reception of a key-info request. In addition, it may contain
 *                 the sender's key information, if available.
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
    private _olmAccount: any;
    private _idKeys: any;
    static events: {
        PARTICIPANT_E2EE_CHANNEL_READY: string;
        PARTICIPANT_SAS_AVAILABLE: string;
        PARTICIPANT_SAS_READY: string;
        PARTICIPANT_KEY_UPDATED: string;
        PARTICIPANT_VERIFICATION_COMPLETED: string;
        GENERATE_KEYS: string;
    };
    //  Used to lock session initializations while initSession was called but not finished yet.
    private _sessionInitializationInProgress = null;

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

        this._sessionInitializationInProgress = null;

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
     *
     * @returns {Promise<void>}
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

            return true;
        } catch (error) {
            logger.error("Failed to initialize Olm", error);
            return false;
        }
    }

    /**
     * Returns the current participants conference ID.
     */
    get myId(): string {
        return this._conf.myUserId();
    }

    async sendKeyInfoToAll() {
        const promises = [];

        for (const participant of this._conf.getParticipants()) {
            const pId = participant.getId();
            const olmData = this._getParticipantOlmData(participant);

            if (olmData.status === PROTOCOL_STATUS.DONE) {
                try {
                    const uuid = uuidv4();
                    const { ciphertextBase64, ivBase64 } =
                        await encryptKeyInfoPQ(
                            olmData.pqSessionKey,
                            this._mediaKeyPQ,
                        );

                    const sessionPromise = new Promise((resolve, reject) => {
                        // Saving resolve function to be able to resolve this function later.
                        this._reqs.set(uuid, { resolve, reject });
                    });

                    promises.push(sessionPromise);

                    const olmCiphertext = this._encryptKeyInfo(olmData.session);
                    this._sendKeyInfoMessage(
                        uuid,
                        olmCiphertext,
                        ciphertextBase64,
                        ivBase64,
                        pId,
                    );
                } catch (error) {
                    this._sendError(
                        pId,
                        `Sending KEY_INFO failed for ${participant.getDisplayName()}: ${error}`,
                    );
                }
            } else {
                this._sendStatusError(
                    pId,
                    participant.getDisplayName(),
                    olmData.status,
                    OLM_MESSAGE_TYPES.KEY_INFO,
                );
            }
        }

        await Promise.allSettled(promises);
    }

    /**
     * Starts new olm sessions with every other participant that has the participantId "smaller" the localParticipantId.
     */
    async initSessions() {
        logger.debug("initSessions called");

        if (this._sessionInitializationInProgress) {
            return this._sessionInitializationInProgress;
        }

        if (!(await this._olmWasInitialized))
            throw new Error(
                "Cannot init sessions because olm was not initialized",
            );

        this._sessionInitializationInProgress = (async () => {
            try {
                const localParticipantId = this._conf.myUserId();
                const participants = this._conf.getParticipants();

                const promises = participants
                    .filter(
                        (participant) =>
                            participant.hasFeature(FEATURE_E2EE) &&
                            localParticipantId < participant.getId(),
                    )
                    .map((participant) =>
                        this._sendSessionInit(participant).catch((error) => {
                            logger.warn(
                                `Failed to initialize session with ${participant.getId()}:`,
                                error,
                            );
                        }),
                    );

                await Promise.all(promises);
            } finally {
                // Clean the session initialization state when promise solved or rejected
                this._sessionInitializationInProgress = null;
            }
        })();

        return this._sessionInitializationInProgress;
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
     * Updates the current participant key and distributes it to all participants in the conference
     * by sending a key-info message.
     *
     * @param {Uint8Array|boolean} key - The new key.
     * @param {Uint8Array|boolean} pqKey - The new key.
     * @retrns {Promise<Number>}
     */
    async updateKey(key: Uint8Array, pqkey: Uint8Array): Promise<number> {
        this.updateCurrentMediaKey(key, pqkey);
        this._mediaKeyIndex++;

        await this.sendKeyInfoToAll();
        // TODO: retry failed ones?

        return this._mediaKeyIndex;
    }

    /**
     * Updates the current participant key.
     * @param {Uint8Array} olmKey - The new key.
     * @param {Uint8Array} pqKey - The new PQ key.
     * @returns {number}
     */
    updateCurrentMediaKey(olmKey: Uint8Array, pqKey: Uint8Array): number {
        this._mediaKeyOlm = olmKey;
        this._mediaKeyPQ = pqKey;

        return this._mediaKeyIndex;
    }

    /**
     * Frees the olmData session for the given participant.
     *
     */
    clearParticipantSession(participant: JitsiParticipant) {
        const olmData = this._getParticipantOlmData(participant);

        if (olmData.session) {
            olmData.session.free();
            olmData.session = undefined;
        }
    }

    /**
     * Frees the olmData sessions for all participants.
     *
     */
    clearAllParticipantsSessions() {
        for (const participant of this._conf.getParticipants()) {
            this.clearParticipantSession(participant);
        }
    }

    /**
     * Sends sacMac if channel verification waas successful.
     *
     */
    markParticipantVerified(participant: JitsiParticipant, isVerified) {
        const olmData = this._getParticipantOlmData(participant);

        const pId = participant.getId();

        if (!isVerified) {
            olmData.sasVerification = undefined;
            logger.warn(`Verification failed for participant ${pId}`);
            this.eventEmitter.emit(
                OlmAdapterEvents.PARTICIPANT_VERIFICATION_COMPLETED,
                pId,
                false,
                E2EEErrors.E2EE_SAS_CHANNEL_VERIFICATION_FAILED,
            );

            return;
        }

        if (!olmData.sasVerification) {
            logger.warn(
                `Participant ${pId} does not have valid sasVerification`,
            );
            this.eventEmitter.emit(
                OlmAdapterEvents.PARTICIPANT_VERIFICATION_COMPLETED,
                pId,
                false,
                E2EEErrors.E2EE_SAS_INVALID_SAS_VERIFICATION,
            );

            return;
        }

        const { sas, sasMacSent } = olmData.sasVerification;

        if (sas && sas.is_their_key_set() && !sasMacSent) {
            this._sendSasMac(participant);

            // Mark the MAC as sent so we don't send it multiple times.
            olmData.sasVerification.sasMacSent = true;
        }
    }

    /**
     * Starts the verification process for the given participant as described here
     * https://spec.matrix.org/latest/client-server-api/#short-authentication-string-sas-verification
     *
     *    |                                 |
          | m.key.verification.start        |
          |-------------------------------->|
          |                                 |
          |       m.key.verification.accept |
          |<--------------------------------|
          |                                 |
          | m.key.verification.key          |
          |-------------------------------->|
          |                                 |
          |          m.key.verification.key |
          |<--------------------------------|
          |                                 |
          | m.key.verification.mac          |
          |-------------------------------->|
          |                                 |
          |          m.key.verification.mac |
          |<--------------------------------|
          |                                 |
     *
     * @param {JitsiParticipant} participant - The target participant.
     * @returns {Promise<void>}
     * @private
     */
    startVerification(participant: JitsiParticipant) {
        const pId = participant.getId();
        const olmData = this._getParticipantOlmData(participant);

        if (!olmData.session) {
            logger.warn(
                `Tried to start verification with participant ${pId} but we have no session`,
            );

            return;
        }

        if (olmData.sasVerification) {
            logger.warn(
                `There is already a verification in progress with participant ${pId}`,
            );

            return;
        }

        olmData.sasVerification = {
            sas: new window.Olm.SAS(),
            transactionId: uuidv4(),
        };

        const startContent = {
            transactionId: olmData.sasVerification.transactionId,
        };

        olmData.sasVerification.startContent = startContent;
        olmData.sasVerification.isInitiator = true;

        const startMessage = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.SAS_START,
                data: startContent,
            },
        };

        this._sendMessage(startMessage, pId);
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
     * Event posted when the E2EE signalling channel has been established with the given participant.
     * @private
     */
    _onParticipantE2EEChannelReady(id) {
        logger.info(
            `E2EE channel with participant ${id} is ready. Ready for KEY_INFO`,
        );
    }

    /**
     * Internal helper for encrypting the current key information for a given participant.
     *
     * @param {Olm.Session} session - Participant's session.
     * @returns {string} - The encrypted text with the key information.
     * @private
     */
    _encryptKeyInfo(session) {
        const keyInfo: KeyInfo = { encryptionKey: undefined, index: -1 };

        if (this._mediaKeyOlm !== undefined) {
            keyInfo.encryptionKey = this._mediaKeyOlm
                ? base64js.fromByteArray(this._mediaKeyOlm)
                : false;
            keyInfo.index = this._mediaKeyIndex;
        }

        return session.encrypt(JSON.stringify(keyInfo));
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
                this._onParticipantLeft(participant);
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
        participantName: string,
        protocolStatus: string,
        recivedMessageType: string,
    ): Promise<void> {
        this._sendError(
            participantID,
            `Got ${recivedMessageType} from ${participantName} but protocol status is ${protocolStatus}`,
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
        publicKey: string,
        pId: string,
    ): Promise<void> {
        const init = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.SESSION_INIT,
                data: {
                    idKey,
                    otKey,
                    publicKey,
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
        publicKey: string,
        pqCiphertext: string,
        pId: string,
    ): Promise<void> {
        const ack = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.PQ_SESSION_INIT,
                data: {
                    uuid,
                    publicKey,
                    pqCiphertext,
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
        pqCiphertext: string,
        pId: string,
    ): Promise<void> {
        const ack = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.PQ_SESSION_ACK,
                data: {
                    uuid,
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
        ciphertext: string,
        pId: string,
    ): Promise<void> {
        const ack = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.SESSION_ACK,
                data: {
                    ciphertext,
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
        iv: string,
        pId: string,
    ): Promise<void> {
        const info = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.KEY_INFO,
                data: {
                    ciphertext,
                    pqCiphertext,
                    iv,
                    uuid,
                },
            },
        };
        this._sendMessage(info, pId);
    }

    /**
     * Sends KEY_INFO_ACK message
     *
     * @private
     */
    async _sendKeyInfoAckMessage(
        uuid: string,
        ciphertext: string,
        pqCiphertext: string,
        iv: string,
        pId: string,
    ): Promise<void> {
        const ack = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.KEY_INFO_ACK,
                data: {
                    ciphertext,
                    pqCiphertext,
                    iv,
                    uuid: uuid,
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
                "_onEndpointMessageReceived: Incorrectly formatted message: ",
            );

            return;
        }

        if (!(await this._olmWasInitialized)) {
            throw new Error("Olm not initialized");
        }

        const msg = payload.olm;
        const peerName = participant.getDisplayName();
        const pId = participant.getId();

        try {
            const uuid = msg.data.uuid;
            const olmData = this._getParticipantOlmData(participant);

            switch (msg.type) {
                case OLM_MESSAGE_TYPES.SESSION_INIT: {
                    if (olmData.status === PROTOCOL_STATUS.NOT_STARTED) {
                        this.eventEmitter.emit(OlmAdapterEvents.GENERATE_KEYS);
                        const session = new window.Olm.Session();
                        session.create_outbound(
                            this._olmAccount,
                            msg.data.idKey,
                            msg.data.otKey,
                        );
                        olmData.session = session;

                        const { ciphertextBase64, sharedSecret } =
                            await encapsulateSecret(msg.data.publicKey);
                        olmData._kemSecret = sharedSecret;

                        this._sendPQSessionInitMessage(
                            uuid,
                            this._publicKeyBase64,
                            ciphertextBase64,
                            pId,
                        );

                        olmData.status = PROTOCOL_STATUS.WAITING_PQ_SESSION_ACK;
                    } else
                        this._sendStatusError(
                            pId,
                            peerName,
                            msg.type,
                            olmData.status,
                        );
                    break;
                }

                case OLM_MESSAGE_TYPES.PQ_SESSION_INIT: {
                    if (
                        olmData.status ===
                        PROTOCOL_STATUS.WAITING_PQ_SESSION_INIT
                    ) {
                        const { ciphertextBase64, sharedSecret } =
                            await encapsulateSecret(msg.data.publicKey);

                        olmData.pqSessionKey = await decapsulateAndDeriveOneKey(
                            msg.data.pqCiphertext,
                            this._privateKey,
                            sharedSecret,
                            true,
                        );

                        this._sendPQSessionAckMessage(
                            uuid,
                            ciphertextBase64,
                            pId,
                        );
                        olmData.status = PROTOCOL_STATUS.WAITING_SESSION_ACK;
                    } else
                        this._sendStatusError(
                            pId,
                            peerName,
                            msg.type,
                            olmData.status,
                        );
                    break;
                }
                case OLM_MESSAGE_TYPES.PQ_SESSION_ACK: {
                    if (
                        olmData.status ===
                        PROTOCOL_STATUS.WAITING_PQ_SESSION_ACK
                    ) {
                        olmData.pqSessionKey = await decapsulateAndDeriveOneKey(
                            msg.data.pqCiphertext,
                            this._privateKey,
                            olmData._kemSecret,
                            false,
                        );
                        const olmCiphertext = this._encryptKeyInfo(
                            olmData.session,
                        );
                        this._sendSessionAckMessage(uuid, olmCiphertext, pId);

                        olmData.status = PROTOCOL_STATUS.DONE;
                        this._onParticipantE2EEChannelReady(peerName);
                    } else
                        this._sendStatusError(
                            pId,
                            peerName,
                            msg.type,
                            olmData.status,
                        );
                    break;
                }
                case OLM_MESSAGE_TYPES.SESSION_ACK: {
                    if (
                        olmData.status === PROTOCOL_STATUS.WAITING_SESSION_ACK
                    ) {
                        const { ciphertext } = msg.data;
                        const requestPromise = this._reqs.get(uuid);
                        const session = new window.Olm.Session();

                        session.create_inbound(
                            this._olmAccount,
                            ciphertext.body,
                        );

                        // Remove OT keys that have been used to setup this session.
                        this._olmAccount.remove_one_time_keys(session);
                        olmData.session = session;
                        olmData.pendingSessionUuid = undefined;
                        olmData.status = PROTOCOL_STATUS.DONE;

                        this._onParticipantE2EEChannelReady(peerName);

                        requestPromise.resolve();

                        this._reqs.delete(uuid);
                    } else
                        this._sendStatusError(
                            pId,
                            peerName,
                            msg.type,
                            olmData.status,
                        );
                    break;
                }
                case OLM_MESSAGE_TYPES.ERROR: {
                    this._sendError(pId, msg.data.error);
                    break;
                }
                case OLM_MESSAGE_TYPES.KEY_INFO: {
                    if (olmData.status === PROTOCOL_STATUS.DONE) {
                        const { ciphertext, pqCiphertext, iv } = msg.data;
                        const data = olmData.session.decrypt(
                            ciphertext.type,
                            ciphertext.body,
                        );
                        const json = safeJsonParse(data);
                        const pqKey = await decryptKeyInfoPQ(
                            pqCiphertext,
                            iv,
                            olmData.pqSessionKey,
                        );

                        if (
                            json.encryptionKey !== undefined &&
                            pqKey !== undefined &&
                            json.index !== undefined
                        ) {
                            const key = json.encryptionKey
                                ? base64js.toByteArray(json.encryptionKey)
                                : false;
                            const keyIndex = json.index;

                            if (!isEqual(olmData.lastKey, key)) {
                                olmData.lastKey = key;
                                this.eventEmitter.emit(
                                    OlmAdapterEvents.PARTICIPANT_KEY_UPDATED,
                                    pId,
                                    key,
                                    pqKey,
                                    keyIndex,
                                );
                            }

                            const { ciphertextBase64, ivBase64 } =
                                await encryptKeyInfoPQ(
                                    olmData.pqSessionKey,
                                    this._mediaKeyPQ,
                                );

                            const olmCiphertext = this._encryptKeyInfo(
                                olmData.session,
                            );
                            this._sendKeyInfoAckMessage(
                                uuid,
                                olmCiphertext,
                                ciphertextBase64,
                                ivBase64,
                                pId,
                            );
                        }
                    } else
                        this._sendStatusError(
                            pId,
                            peerName,
                            msg.type,
                            olmData.status,
                        );
                    break;
                }
                case OLM_MESSAGE_TYPES.KEY_INFO_ACK: {
                    if (olmData.status === PROTOCOL_STATUS.DONE) {
                        const { ciphertext, pqCiphertext, iv } = msg.data;
                        const data = olmData.session.decrypt(
                            ciphertext.type,
                            ciphertext.body,
                        );
                        const json = safeJsonParse(data);

                        const pqKey = await decryptKeyInfoPQ(
                            pqCiphertext,
                            iv,
                            olmData.pqSessionKey,
                        );

                        if (
                            json.encryptionKey !== undefined &&
                            pqKey !== undefined &&
                            json.index !== undefined
                        ) {
                            const key = json.encryptionKey
                                ? base64js.toByteArray(json.encryptionKey)
                                : false;
                            const keyIndex = json.index;

                            if (!isEqual(olmData.lastKey, key)) {
                                olmData.lastKey = key;

                                this.eventEmitter.emit(
                                    OlmAdapterEvents.PARTICIPANT_KEY_UPDATED,
                                    pId,
                                    key,
                                    pqKey,
                                    keyIndex,
                                );
                            }
                        }
                        const sessionPromise = this._reqs.get(uuid);

                        sessionPromise.resolve();

                        this._reqs.delete(uuid);
                    } else
                        this._sendStatusError(
                            pId,
                            peerName,
                            msg.type,
                            olmData.status,
                        );
                    break;
                }
                case OLM_MESSAGE_TYPES.SAS_START: {
                    if (!olmData.session) {
                        this._sendError(
                            pId,
                            "No session found while processing sas-init",
                        );

                        return;
                    }

                    if (olmData.sasVerification?.sas) {
                        logger.warn(
                            `SAS already created for participant ${pId}`,
                        );
                        this.eventEmitter.emit(
                            OlmAdapterEvents.PARTICIPANT_VERIFICATION_COMPLETED,
                            pId,
                            false,
                            E2EEErrors.E2EE_SAS_INVALID_SAS_VERIFICATION,
                        );

                        return;
                    }

                    const { transactionId } = msg.data;

                    const sas = new window.Olm.SAS();

                    olmData.sasVerification = {
                        sas,
                        transactionId,
                        isInitiator: false,
                    };

                    const pubKey = olmData.sasVerification.sas.get_pubkey();
                    const commitment = this._computeCommitment(
                        pubKey,
                        msg.data,
                    );

                    /* The first phase of the verification process, the Key agreement phase
                https://spec.matrix.org/latest/client-server-api/#short-authentication-string-sas-verification
            */
                    const acceptMessage = {
                        [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
                        olm: {
                            type: OLM_MESSAGE_TYPES.SAS_ACCEPT,
                            data: {
                                transactionId,
                                commitment,
                            },
                        },
                    };

                    this._sendMessage(acceptMessage, pId);
                    break;
                }
                case OLM_MESSAGE_TYPES.SAS_ACCEPT: {
                    if (!olmData.session) {
                        this._sendError(
                            pId,
                            "No session found while processing sas-accept",
                        );

                        return;
                    }

                    const { commitment, transactionId } = msg.data;

                    if (!olmData.sasVerification) {
                        logger.warn(
                            `SAS_ACCEPT Participant ${pId} does not have valid sasVerification`,
                        );
                        this.eventEmitter.emit(
                            OlmAdapterEvents.PARTICIPANT_VERIFICATION_COMPLETED,
                            pId,
                            false,
                            E2EEErrors.E2EE_SAS_INVALID_SAS_VERIFICATION,
                        );

                        return;
                    }

                    if (olmData.sasVerification.sasCommitment) {
                        this._sendError(
                            pId,
                            "Already received sas commitment message from ${pId}!",
                        );

                        return;
                    }

                    olmData.sasVerification.sasCommitment = commitment;

                    const pubKey = olmData.sasVerification.sas.get_pubkey();

                    // Send KEY.
                    const keyMessage = {
                        [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
                        olm: {
                            type: OLM_MESSAGE_TYPES.SAS_KEY,
                            data: {
                                key: pubKey,
                                transactionId,
                            },
                        },
                    };

                    this._sendMessage(keyMessage, pId);

                    olmData.sasVerification.keySent = true;
                    break;
                }
                case OLM_MESSAGE_TYPES.SAS_KEY: {
                    if (!olmData.session) {
                        this._sendError(
                            pId,
                            "No session found while processing sas-key",
                        );

                        return;
                    }

                    if (!olmData.sasVerification) {
                        logger.warn(
                            `SAS_KEY Participant ${pId} does not have valid sasVerification`,
                        );
                        this.eventEmitter.emit(
                            OlmAdapterEvents.PARTICIPANT_VERIFICATION_COMPLETED,
                            pId,
                            false,
                            E2EEErrors.E2EE_SAS_INVALID_SAS_VERIFICATION,
                        );

                        return;
                    }

                    const {
                        isInitiator,
                        sas,
                        sasCommitment,
                        startContent,
                        keySent,
                    } = olmData.sasVerification;

                    if (sas.is_their_key_set()) {
                        logger.warn("SAS already has their key!");

                        return;
                    }

                    const { key: theirKey, transactionId } = msg.data;

                    if (sasCommitment) {
                        const commitment = this._computeCommitment(
                            theirKey,
                            startContent,
                        );

                        if (sasCommitment !== commitment) {
                            this._sendError(
                                pId,
                                "OlmAdapter commitments mismatched",
                            );
                            this.eventEmitter.emit(
                                OlmAdapterEvents.PARTICIPANT_VERIFICATION_COMPLETED,
                                pId,
                                false,
                                E2EEErrors.E2EE_SAS_COMMITMENT_MISMATCHED,
                            );
                            olmData.sasVerification.free();

                            return;
                        }
                    }

                    sas.set_their_key(theirKey);

                    const pubKey = sas.get_pubkey();

                    const myInfo = `${this.myId}|${pubKey}`;
                    const theirInfo = `${pId}|${theirKey}`;

                    const info = isInitiator
                        ? `${myInfo}|${theirInfo}`
                        : `${theirInfo}|${myInfo}`;

                    const sasBytes = sas.generate_bytes(
                        info,
                        OLM_SAS_NUM_BYTES,
                    );
                    const generatedSas = generateSas(sasBytes);

                    this.eventEmitter.emit(
                        OlmAdapterEvents.PARTICIPANT_SAS_READY,
                        pId,
                        generatedSas,
                    );

                    if (keySent) {
                        return;
                    }

                    const keyMessage = {
                        [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
                        olm: {
                            type: OLM_MESSAGE_TYPES.SAS_KEY,
                            data: {
                                key: pubKey,
                                transactionId,
                            },
                        },
                    };

                    this._sendMessage(keyMessage, pId);

                    olmData.sasVerification.keySent = true;
                    break;
                }
                case OLM_MESSAGE_TYPES.SAS_MAC: {
                    if (!olmData.session) {
                        this._sendError(
                            pId,
                            "No session found while processing sas-mac",
                        );

                        return;
                    }

                    const { keys, mac, transactionId } = msg.data;

                    if (!mac || !keys) {
                        logger.warn("Invalid SAS MAC message");

                        return;
                    }

                    if (!olmData.sasVerification) {
                        logger.warn(
                            `SAS_MAC Participant ${pId} does not have valid sasVerification`,
                        );

                        return;
                    }

                    const sas = olmData.sasVerification.sas;

                    // Verify the received MACs.
                    const baseInfo = `${OLM_KEY_VERIFICATION_MAC_INFO}${pId}${this.myId}${transactionId}`;
                    const keysMac = sas.calculate_mac(
                        Object.keys(mac).sort().join(","),
                        baseInfo + OLM_KEY_VERIFICATION_MAC_KEY_IDS,
                    );

                    if (keysMac !== keys) {
                        logger.error(
                            "SAS verification error: keys MAC mismatch",
                        );
                        this.eventEmitter.emit(
                            OlmAdapterEvents.PARTICIPANT_VERIFICATION_COMPLETED,
                            pId,
                            false,
                            E2EEErrors.E2EE_SAS_KEYS_MAC_MISMATCH,
                        );

                        return;
                    }

                    if (!olmData.ed25519) {
                        logger.warn(
                            "SAS verification error: Missing ed25519 key",
                        );

                        this.eventEmitter.emit(
                            OlmAdapterEvents.PARTICIPANT_VERIFICATION_COMPLETED,
                            pId,
                            false,
                            E2EEErrors.E2EE_SAS_MISSING_KEY,
                        );

                        return;
                    }

                    for (const [keyInfo, computedMac] of Object.entries(mac)) {
                        const ourComputedMac = sas.calculate_mac(
                            olmData.ed25519,
                            baseInfo + keyInfo,
                        );

                        if (computedMac !== ourComputedMac) {
                            logger.error(
                                "SAS verification error: MAC mismatch",
                            );
                            this.eventEmitter.emit(
                                OlmAdapterEvents.PARTICIPANT_VERIFICATION_COMPLETED,
                                pId,
                                false,
                                E2EEErrors.E2EE_SAS_MAC_MISMATCH,
                            );

                            return;
                        }
                    }

                    this.eventEmitter.emit(
                        OlmAdapterEvents.PARTICIPANT_VERIFICATION_COMPLETED,
                        pId,
                        true,
                    );

                    break;
                }
            }
        } catch (error) {
            this._sendError(
                pId,
                `Processing ${msg.type} failed for ${peerName}: ${error}`,
            );
        }
    }

    /**
     * Handles a participant leaving. When a participant leaves their olm session is destroyed.
     *
     * @private
     */
    _onParticipantLeft(participant: JitsiParticipant) {
        this.clearParticipantSession(participant);
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
        switch (name) {
            case "e2ee.enabled":
                if (newValue && this._conf.isE2EEEnabled()) {
                    if (!(await this._olmWasInitialized)) {
                        throw new Error(
                            "_onParticipantPropertyChanged is called before init",
                        );
                    }
                    await this.sendKeyInfoToAll();
                }
                break;
            case "e2ee.idKey.ed25519":
                {
                    const olmData = this._getParticipantOlmData(participant);
                    olmData.ed25519 = newValue;
                    const participantId = participant.getId();
                    this.eventEmitter.emit(
                        OlmAdapterEvents.PARTICIPANT_SAS_AVAILABLE,
                        participantId,
                    );
                }
                break;
        }
    }

    /**
     * Builds and sends an error message to the target participant.
     *
     * @param {string} id - The target participant.
     * @param {string} error - The error message.
     * @returns {void}
     */
    _sendError(pId: string, error) {
        logger.error(error);
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
        logger.debug(`sendMessage ${JSON.stringify(data)} to `, participantId);
        this._conf.sendMessage(data, participantId);
    }

    /**
     * Builds and sends the session-init request to the target participant.
     *
     * @param {JitsiParticipant} participant - Participant to whom we'll send the request.
     * @returns {Promise} - The promise will be resolved when the session-ack is received.
     * @private
     */
    async _sendSessionInit(participant: JitsiParticipant) {
        const pId = participant.getId();
        const olmData = this._getParticipantOlmData(participant);

        if (olmData.status === PROTOCOL_STATUS.DONE) {
            logger.warn(`Tried to send session-init to ${participant.getDisplayName()} 
            but we already have a session`);

            throw new Error(
                `Already have a session with participant ${participant.getDisplayName()} `,
            );
        }

        if (olmData.status === PROTOCOL_STATUS.NOT_STARTED) {
            try {
                this.eventEmitter.emit(OlmAdapterEvents.GENERATE_KEYS);

                // Generate a One Time Key.
                this._olmAccount.generate_one_time_keys(1);

                const otKeys = _safeJsonParse(this._olmAccount.one_time_keys());
                const values = Object.values(otKeys.curve25519);

                if (!values.length || typeof values[0] !== "string") {
                    return Promise.reject(
                        new Error("No one-time-keys generated"),
                    );
                }

                const otKey: string = values[0];

                // Mark the OT keys (one really) as published so they are not reused.
                this._olmAccount.mark_keys_as_published();

                const uuid = uuidv4();

                const sessionPromise = new Promise((resolve, reject) => {
                    this._reqs.set(uuid, { resolve, reject });
                });

                const timeoutPromise = new Promise((_, reject) =>
                    setTimeout(
                        () =>
                            reject(new Error("Session init request timed out")),
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
                olmData.pendingSessionUuid = uuid;

                // Simulates timeout with deferred object but using promises
                return Promise.race([sessionPromise, timeoutPromise]).catch(
                    (error) => {
                        this._reqs.delete(uuid);
                        olmData.pendingSessionUuid = undefined;
                        throw error;
                    },
                );
            } catch (e) {
                this._sendError(
                    pId,
                    `sendSessionInit failed for ${participant.getDisplayName()}: ${e}`,
                );
            }
        } else {
            this._sendError(
                pId,
                `Trying to send SESSION_INIT to ${participant.getDisplayName()} but status is ${olmData.status}`,
            );
        }
    }

    /**
     * Builds and sends the SAS MAC message to the given participant.
     * The second phase of the verification process, the Key verification phase
        https://spec.matrix.org/latest/client-server-api/#short-authentication-string-sas-verification
     */
    _sendSasMac(participant: JitsiParticipant) {
        const pId = participant.getId();
        const olmData = this._getParticipantOlmData(participant);
        const { sas, transactionId } = olmData.sasVerification;

        // Calculate and send MAC with the keys to be verified.
        const mac = {};
        const keyList = [];
        const baseInfo = `${OLM_KEY_VERIFICATION_MAC_INFO}${this.myId}${pId}${transactionId}`;

        const deviceKeyId = `ed25519:${pId}`;

        mac[deviceKeyId] = sas.calculate_mac(
            this._idKeys.ed25519,
            baseInfo + deviceKeyId,
        );
        keyList.push(deviceKeyId);

        const keys = sas.calculate_mac(
            keyList.sort().join(","),
            baseInfo + OLM_KEY_VERIFICATION_MAC_KEY_IDS,
        );

        const macMessage = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.SAS_MAC,
                data: {
                    keys,
                    mac,
                    transactionId,
                },
            },
        };

        this._sendMessage(macMessage, pId);
    }

    /**
     * Computes the commitment.
     */
    _computeCommitment(pubKey, data) {
        const olmUtil = new window.Olm.Utility();
        const commitment = olmUtil.sha256(pubKey + JSON.stringify(data));

        olmUtil.free();

        return commitment;
    }
}

/**
 * Helper to ensure JSON parsing always returns an object.
 *
 * @param {string} data - The data that needs to be parsed.
 * @returns {object} - Parsed data or empty object in case of failure.
 */
function safeJsonParse(data) {
    try {
        return _safeJsonParse(data);
    } catch (e) {
        logger.error(`Cannot parse date ${data}: ${e}`);
        return {};
    }
}

OlmAdapter.events = OlmAdapterEvents;
