/* global Olm */

import { safeJsonParse as _safeJsonParse } from "@jitsi/js-utils/json";
import { getLogger } from "@jitsi/logger";
import base64js from "base64-js";
import { Buffer } from "buffer";
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

const REQ_TIMEOUT = 5 * 1000;
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
    private _init: Promise<void>;
    private _mediaKeyOlm: Uint8Array;
    private _mediaKeyPQ: Uint8Array;
    private _mediaKeyIndex: number;
    private _reqs: Map<
        Uint8Array,
        { resolve: (args?: unknown) => void; reject?: (args?: unknown) => void }
    >;
    private _publicKeyBase64: String;
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
        this._init = this._bootstrapOlm();

        if (OlmAdapter.isSupported()) {
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
            this._init = Promise.reject(new Error("Olm not supported"));
        }
    }

    /**
     * Initializes the Olm library and sets up the account.
     *
     * @returns {Promise<void>}
     * @private
     */
    async _bootstrapOlm(): Promise<void> {
        if (!OlmAdapter.isSupported()) {
            throw new Error("Olm is not supported on this platform.");
        }

        try {
            await window.Olm.init();

            this._olmAccount = new window.Olm.Account();
            this._olmAccount.create();

            this._idKeys = safeJsonParse(this._olmAccount.identity_keys());

            logger.debug(
                `Olm ${window.Olm.get_library_version().join(".")} initialized`,
            );

            await this._initializeKemAndKeys();
            this._onIdKeysReady(this._idKeys);
        } catch (e) {
            logger.error("Failed to initialize Olm", e);
            throw e;
        }
    }

    /**
     * Returns the current participants conference ID.
     */
    get myId(): string {
        return this._conf.myUserId();
    }

    async sendKeyInfoToAll() {
        // Broadcast it.
        logger.debug(
            `Send key info to all called ${{
                participants: this._conf.getParticipants(),
            }}`,
        );

        const promises = [];

        for (const participant of this._conf.getParticipants()) {
            const pId = participant.getId();
            const olmData = this._getParticipantOlmData(participant);

            // TODO: skip those who don't support E2EE.
            if (!olmData.session || !olmData.pqSessionKey) {
                logger.warn(`Tried to send KEY_INFO to participant ${participant.getDisplayName()} 
                     but we have no session
                     ${olmData.session} and ${olmData.pqSessionKey}`);

                continue;
            }

            const uuid = uuidv4();
            const { ciphertextBase64, ivBase64 } = await encryptKeyInfoPQ(
                olmData.pqSessionKey,
                this._mediaKeyPQ,
            );

            const data = {
                [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
                olm: {
                    type: OLM_MESSAGE_TYPES.KEY_INFO,
                    data: {
                        ciphertext: this._encryptKeyInfo(olmData.session),
                        pqCiphertext: ciphertextBase64,
                        iv: ivBase64,
                        uuid,
                    },
                },
            };

            const sessionPromise = new Promise((resolve, reject) => {
                // Saving resolve function to be able to resolve this function later.
                this._reqs.set(uuid, { resolve, reject });
            });

            promises.push(sessionPromise);

            this._sendMessage(data, pId);
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

        this._sessionInitializationInProgress = (async () => {
            try {
                // Wait for Olm library to initialize
                await this._init;

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
     * Initializes kem and creates key pair
     * @returns {Promise<{ publicKey: Uint8Array, privateKey: Uint8Array }>}
     * @private
     */
    async _initializeKemAndKeys() {
        const { publicKeyBase64, privateKey } = await generateKyberKeys();

        this._publicKeyBase64 = publicKeyBase64;
        this._privateKey = privateKey;
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
            if (idKeys.hasOwnProperty(keyType)) {
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
        logger.debug(
            `CHECK: E2EE channel with participant ${id} is ready. Ready for KEY_INFO`,
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
        let keyInfo: KeyInfo = { encryptionKey: undefined, index: -1 };

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

        return participant[kOlmData];
    }

    /**
     * Handles leaving the conference, cleaning up olm sessions.
     *
     * @private
     */
    async _onConferenceLeft() {
        await this._init;
        for (const participant of this._conf.getParticipants()) {
            this._onParticipantLeft(participant);
        }

        if (this._olmAccount) {
            this._olmAccount.free();
            this._olmAccount = undefined;
        }
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

        if (!this._init) {
            throw new Error("Olm not initialized");
        }

        const msg = payload.olm;
        const uuid = msg.data.uuid;
        const pId = participant.getId();
        const olmData = this._getParticipantOlmData(participant);
        const peerName = participant.getDisplayName();

        switch (msg.type) {
            case OLM_MESSAGE_TYPES.SESSION_INIT: {
                if (olmData.session) {
                    this._sendError(
                        participant,
                        `SESSION_INIT: Session with ${peerName} already established`,
                    );
                } else {
                    try {
                        this.eventEmitter.emit(OlmAdapterEvents.GENERATE_KEYS);

                        // Create a session for communicating with this participant.
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

                        const ack = {
                            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
                            olm: {
                                type: OLM_MESSAGE_TYPES.PQ_SESSION_INIT,
                                data: {
                                    uuid,
                                    publicKey: this._publicKeyBase64,
                                    pqCiphertext: ciphertextBase64,
                                },
                            },
                        };

                        this._sendMessage(ack, pId);
                    } catch (error) {
                        this._sendError(
                            participant,
                            `SESSION_INIT failed for ${peerName} with ${error}`,
                        );
                    }
                }
                break;
            }

            case OLM_MESSAGE_TYPES.PQ_SESSION_INIT: {
                if (olmData.pqSessionKey) {
                    this._sendError(
                        participant,
                        `PQ_SESSION_INIT: Session for ${peerName} already established`,
                    );
                } else {
                    try {
                        const { ciphertextBase64, sharedSecret } =
                            await encapsulateSecret(msg.data.publicKey);

                        olmData.pqSessionKey = await decapsulateAndDeriveOneKey(
                            msg.data.pqCiphertext,
                            this._privateKey,
                            sharedSecret,
                        );

                        const ack = {
                            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
                            olm: {
                                type: OLM_MESSAGE_TYPES.PQ_SESSION_ACK,
                                data: {
                                    uuid,
                                    pqCiphertext: ciphertextBase64,
                                },
                            },
                        };
                        this._sendMessage(ack, pId);
                    } catch (error) {
                        this._sendError(
                            participant,
                            `PQ_SESSION_INIT ${msg.data} failed for ${peerName} with ${error}`,
                        );
                    }
                }
                break;
            }
            case OLM_MESSAGE_TYPES.PQ_SESSION_ACK: {
                logger.debug("CHECK: Got PQ_SESSION_ACK from id", pId);

                if (olmData.pqSessionKey) {
                    this._sendError(
                        participant,
                        `PQ_SESSION_ACK: Session with ${peerName} is already established`,
                    );
                } else {
                    try {
                        olmData.pqSessionKey = await decapsulateAndDeriveOneKey(
                            msg.data.pqCiphertext,
                            this._privateKey,
                            olmData._kemSecret,
                        );

                        const ack = {
                            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
                            olm: {
                                type: OLM_MESSAGE_TYPES.SESSION_ACK,
                                data: {
                                    ciphertext: this._encryptKeyInfo(
                                        olmData.session,
                                    ),
                                    uuid,
                                },
                            },
                        };

                        this._sendMessage(ack, pId);

                        this._onParticipantE2EEChannelReady(peerName);
                    } catch (error) {
                        this._sendError(
                            participant,
                            `PQ_SESSION_ACK failed for ${peerName} with ${error}`,
                        );
                    }
                }
                break;
            }
            case OLM_MESSAGE_TYPES.SESSION_ACK: {
                if (olmData.session) {
                    this._sendError(
                        participant,
                        `Session  with ${peerName} is already established`,
                    );
                } else if (uuid === olmData.pendingSessionUuid) {
                    const { ciphertext } = msg.data;
                    const requestPromise = this._reqs.get(uuid);
                    const session = new window.Olm.Session();

                    session.create_inbound(this._olmAccount, ciphertext.body);

                    // Remove OT keys that have been used to setup this session.
                    this._olmAccount.remove_one_time_keys(session);
                    olmData.session = session;
                    olmData.pendingSessionUuid = undefined;

                    this._onParticipantE2EEChannelReady(peerName);

                    requestPromise.resolve();

                    this._reqs.delete(uuid);
                    logger.debug(`CHECK: RESOLVE SESSION ACK ${uuid}`);
                } else {
                    this._sendError(
                        participant,
                        `SESSION_ACK wrong UUID for ${peerName}`,
                    );
                }
                break;
            }
            case OLM_MESSAGE_TYPES.ERROR: {
                this._sendError(participant, msg.data.error);
                break;
            }
            case OLM_MESSAGE_TYPES.KEY_INFO: {
                if (olmData.session && olmData.pqSessionKey) {
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

                        const ack = {
                            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
                            olm: {
                                type: OLM_MESSAGE_TYPES.KEY_INFO_ACK,
                                data: {
                                    ciphertext: this._encryptKeyInfo(
                                        olmData.session,
                                    ),
                                    pqCiphertext: ciphertextBase64,
                                    iv: ivBase64,
                                    uuid: uuid,
                                },
                            },
                        };

                        this._sendMessage(ack, pId);
                    }
                } else {
                    this._sendError(
                        participant,
                        `Received KEY_INFO from ${peerName} but we have no session for them!`,
                    );
                }
                break;
            }
            case OLM_MESSAGE_TYPES.KEY_INFO_ACK: {

                if (olmData.session && olmData.pqSessionKey) {
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

                    logger.debug("CHECK: RESOLVE KEY_INFO_ACK");
                } else {
                    this._sendError(
                        participant,
                        `Received KEY_INFO_ACK from ${peerName} but we have no session for them!`,
                    );
                }
                break;
            }
            case OLM_MESSAGE_TYPES.SAS_START: {
                if (!olmData.session) {
                    this._sendError(
                        participant,
                        "No session found while processing sas-init",
                    );

                    return;
                }

                if (olmData.sasVerification?.sas) {
                    logger.warn(`SAS already created for participant ${pId}`);
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
                const commitment = this._computeCommitment(pubKey, msg.data);

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
                        participant,
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
                        participant,
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
                        participant,
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
                            participant,
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

                const sasBytes = sas.generate_bytes(info, OLM_SAS_NUM_BYTES);
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
                        participant,
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
                    Object.keys(mac).sort().join(","), // eslint-disable-line newline-per-chained-call
                    baseInfo + OLM_KEY_VERIFICATION_MAC_KEY_IDS,
                );

                if (keysMac !== keys) {
                    logger.error("SAS verification error: keys MAC mismatch");
                    this.eventEmitter.emit(
                        OlmAdapterEvents.PARTICIPANT_VERIFICATION_COMPLETED,
                        pId,
                        false,
                        E2EEErrors.E2EE_SAS_KEYS_MAC_MISMATCH,
                    );

                    return;
                }

                if (!olmData.ed25519) {
                    logger.warn("SAS verification error: Missing ed25519 key");

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
                        logger.error("SAS verification error: MAC mismatch");
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
    }

    /**
     * Handles a participant leaving. When a participant leaves their olm session is destroyed.
     *
     * @private
     */
    _onParticipantLeft(participant: JitsiParticipant) {
        logger.debug("_onParticipantLeft for participant", participant);
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
                if (newValue && !oldValue && this._conf.isE2EEEnabled()) {
                    if (!this._init) {
                        throw new Error(
                            "_onParticipantPropertyChanged is called before init",
                        );
                    }

                    logger.debug(
                        "send key info from _onParticipantPropertyChanged",
                    );
                    await this.sendKeyInfoToAll();
                }
                break;
            case "e2ee.idKey.ed25519":
                const olmData = this._getParticipantOlmData(participant);
                olmData.ed25519 = newValue;
                const participantId = participant.getId();
                this.eventEmitter.emit(
                    OlmAdapterEvents.PARTICIPANT_SAS_AVAILABLE,
                    participantId,
                );
                break;
        }
    }

    /**
     * Builds and sends an error message to the target participant.
     *
     * @param {JitsiParticipant} participant - The target participant.
     * @param {string} error - The error message.
     * @returns {void}
     */
    _sendError(participant: JitsiParticipant, error) {
        logger.error(error);
        const pId = participant.getId();
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

        if (olmData.session) {
            logger.warn(`Tried to send session-init to ${participant.getDisplayName()} 
            but we already have a session`);

            throw new Error(
                `Already have a session with participant ${participant.getDisplayName()} `,
            );
        }

        if (olmData.pendingSessionUuid !== undefined) {
            logger.warn(`Tried to send session-init to ${participant.getDisplayName()} 
         but we already have a pending session`);

            throw new Error(
                `Already have a pending session with participant ${participant.getDisplayName()}`,
            );
        }

        try {
            this.eventEmitter.emit(OlmAdapterEvents.GENERATE_KEYS);

            // Generate a One Time Key.
            this._olmAccount.generate_one_time_keys(1);

            const otKeys = _safeJsonParse(this._olmAccount.one_time_keys());
            const otKey = Object.values(otKeys.curve25519)[0];

            if (!otKey) {
                return Promise.reject(new Error("No one-time-keys generated"));
            }

            // Mark the OT keys (one really) as published so they are not reused.
            this._olmAccount.mark_keys_as_published();

            const uuid = uuidv4();

            const init = {
                [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
                olm: {
                    type: OLM_MESSAGE_TYPES.SESSION_INIT,
                    data: {
                        idKey: this._idKeys.curve25519,
                        otKey,
                        publicKey: this._publicKeyBase64,
                        uuid,
                    },
                },
            };

            const sessionPromise = new Promise((resolve, reject) => {
                this._reqs.set(uuid, { resolve, reject });
            });

            const timeoutPromise = new Promise((_, reject) =>
                setTimeout(
                    () => reject(new Error("Session init request timed out")),
                    REQ_TIMEOUT,
                ),
            );

            this._sendMessage(init, pId);
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
                participant,
                `_sendSessionInit failed for ${participant.getDisplayName()} with ${e}`,
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
        return {};
    }
}

OlmAdapter.events = OlmAdapterEvents;
