/// <reference types="node" />

import browser from "../browser";
import JitsiLocalTrack from "../RTC/JitsiLocalTrack";
import JingleSessionPC from "../xmpp/JingleSessionPC";
import TraceablePeerConnection from "../RTC/TraceablePeerConnection";
import E2EEContext from "./E2EEContext";

import * as JitsiConferenceEvents from "../../JitsiConferenceEvents";
import JitsiParticipant from "../../JitsiParticipant";

import Listenable from "../util/Listenable";
import { OlmAdapter } from "./OlmAdapter";
import JitsiConference from "../../JitsiConference";
import RTCEvents from "../../service/RTC/RTCEvents";
import { generateEmojiSas } from "./crypto-workers";

import { JITSI_MEET_MUC_TYPE, FEATURE_E2EE } from "../xmpp/xmpp";
import { REQ_TIMEOUT } from "./Constants";
import {
    OLM_MESSAGE_TYPE,
    OLM_MESSAGE_TYPES,
    MessageType,
    CustomRTCRtpReceiver,
    CustomRTCRtpSender,
    ReplyMessage,
    SessionError,
    MediaKey,
} from "./Types";

function timeout<T>(ms: number): Promise<T> {
    return new Promise((_, reject) =>
        setTimeout(
            () => reject(new Error("Session init request timed out")),
            ms,
        ),
    );
}

/**
 * This module integrates {@link E2EEContext} with {@link OlmAdapter} in order to distribute the keys for encryption.
 */
export class ManagedKeyHandler extends Listenable {
    conference: JitsiConference;
    e2eeCtx: E2EEContext;
    enabled: boolean;
    initSessions: Promise<unknown[]>;
    _olmAdapter: OlmAdapter;
    private _conferenceJoined: boolean;
    private readonly _reqs: Map<
        string,
        { resolve: (args?: unknown) => void; reject?: (args?: unknown) => void }
    >;

    /**
     * Build a new AutomaticKeyHandler instance, which will be used in a given conference.
     */
    constructor(conference: JitsiConference) {
        super();
        this.conference = conference;
        this.e2eeCtx = new E2EEContext();
        this._reqs = new Map();

        this.enabled = false;

        this.conference.on(
            JitsiConferenceEvents.USER_JOINED,
            this._onParticipantJoined.bind(this),
        );
        this.conference.on(
            JitsiConferenceEvents.USER_LEFT,
            this._onParticipantLeft.bind(this),
        );
        this.conference.on(
            JitsiConferenceEvents.ENDPOINT_MESSAGE_RECEIVED,
            this._onEndpointMessageReceived.bind(this),
        );
        this.conference.on(
            JitsiConferenceEvents.CONFERENCE_LEFT,
            this._onConferenceLeft.bind(this),
        );
        this.conference.on(JitsiConferenceEvents.CONFERENCE_JOINED, () => {
            this._conferenceJoined = true;
        });
        this.conference.on(
            JitsiConferenceEvents._MEDIA_SESSION_STARTED,
            this._onMediaSessionStarted.bind(this),
        );
        this.conference.on(
            JitsiConferenceEvents.TRACK_ADDED,
            (track: JitsiLocalTrack) =>
                track.isLocal() && this._onLocalTrackAdded(track),
        );
        this.conference.rtc.on(
            RTCEvents.REMOTE_TRACK_ADDED,
            (track: JitsiLocalTrack, tpc: TraceablePeerConnection) =>
                this._setupReceiverE2EEForTrack(tpc, track),
        );
        this.conference.on(
            JitsiConferenceEvents.TRACK_MUTE_CHANGED,
            this._trackMuteChanged.bind(this),
        );

        this._conferenceJoined = false;

        this._olmAdapter = new OlmAdapter(conference.myUserId());

        this.e2eeCtx.on("sasUpdated", (sasStr: string) => {
            (async () => {
                const sas = await generateEmojiSas(sasStr);
                this.conference.eventEmitter.emit(
                    JitsiConferenceEvents.E2EE_SAS_AVAILABLE,
                    sas,
                );
            })();
        });
    }
    async init() {
        await this._olmAdapter.init();
    }

    /**
     * Indicates whether E2EE is currently enabled or not.
     *
     * @returns {boolean}
     */
    isEnabled() {
        return this.enabled;
    }

    /**
     * Enables / disables End-To-End encryption.
     *
     * @param {boolean} enabled - whether E2EE should be enabled or not.
     * @returns {void}
     */
    async setEnabled(enabled: boolean) {
        if (enabled === this.enabled) {
            return;
        }
        this.enabled = enabled;

        if (!this._olmAdapter.isInitialized()) {
            await this._olmAdapter.init();
        }

        if (enabled) {
            this.logInfo("Enabling e2ee");
            await this.enableE2E();
        }

        if (!enabled) {
            this.logInfo("Disabling e2ee");
            await this.disableE2E();
        }

        this.conference.setLocalParticipantProperty("e2ee.enabled", enabled);
        this.conference._restartMediaSessions();
    }

    /**
     * Setup E2EE on the new track that has been added to the conference, apply it on all the open peerconnections.
     * @param {JitsiLocalTrack} track - the new track that's being added to the conference.
     * @private
     */
    _onLocalTrackAdded(track: JitsiLocalTrack) {
        for (const session of this.conference.getMediaSessions()) {
            this._setupSenderE2EEForTrack(session, track);
        }
    }

    /**
     * Setups E2E encryption for the new session.
     * @param {JingleSessionPC} session - the new media session.
     * @private
     */
    _onMediaSessionStarted(session: JingleSessionPC) {
        const localTracks = this.conference.getLocalTracks();

        for (const track of localTracks) {
            this._setupSenderE2EEForTrack(session, track);
        }
    }

    /**
     * Enables End-To-End encryption.
     */
    async enableE2E() {
        const localParticipantId = this.conference.myUserId();
        const keyCommitment = this._olmAdapter.getMyIdentityKeysCommitment();
        this.e2eeCtx.setKeysCommitment(localParticipantId, keyCommitment);
        const { olmKey, pqKey, index } = this._olmAdapter.updateMyKeys();
        this.setKey(olmKey, pqKey, index);

        const participants = this.conference.getParticipants();
        const list = participants.filter(
            (participant) =>
                participant.hasFeature(FEATURE_E2EE) &&
                localParticipantId > participant.getId(),
        );
        const keys = this._olmAdapter.generateOneTimeKeys(list.length);
        this.logInfo(
            `My ID is ${localParticipantId}, should send session-init to smaller IDs: [ ${list.map((p) => p.getId())}]`,
        );

        this.initSessions = (async () => {
            const promises = list.map(async (participant) => {
                const pId = participant.getId();
                try {
                    const lastKey = keys.pop();
                    const data =
                        await this._olmAdapter.createSessionInitMessage(
                            pId,
                            lastKey,
                        );
                    this.logInfo(`Sent session-init to participant ${pId}`);
                    this._sendMessage(
                        OLM_MESSAGE_TYPES.SESSION_INIT,
                        data,
                        pId,
                    );

                    const sessionPromise = new Promise((resolve, reject) => {
                        this._reqs.set(pId, { resolve, reject });
                    });

                    const result = await Promise.race([
                        sessionPromise,
                        timeout(REQ_TIMEOUT),
                    ]);
                    this.logInfo(
                        `Session with ${pId} initialized successfully.`,
                    );
                    return result;
                } catch (error) {
                    console.error(
                        `E2E: Failed to initialize session with ${pId}: ${error}`,
                    );
                    this._reqs.delete(pId);
                }
            });

            return Promise.all(promises);
        })();
        await this.initSessions;
    }
    /**
     * Disables End-To-End encryption.
     */
    async disableE2E() {
        this.e2eeCtx.cleanupAll();
        const participants = this.conference.getParticipants();
        for (const participant of participants) {
            this._olmAdapter.clearParticipantSession(participant.getId());
        }
    }

    /**
     * Setup E2EE for the receiving side.
     *
     * @private
     */
    _setupReceiverE2EEForTrack(
        tpc: TraceablePeerConnection,
        track: JitsiLocalTrack,
    ) {
        if (!this.enabled) {
            return;
        }

        const receiver = tpc.findReceiverForTrack(track.track);

        if (receiver) {
            this.e2eeCtx.handleReceiver(
                receiver as CustomRTCRtpReceiver,
                track.getParticipantId(),
            );
        } else {
            console.warn(
                `E2E: Could not handle E2EE for ${track}: receiver not found in: ${tpc}`,
            );
        }
    }

    /**
     * Setup E2EE for the sending side.
     *
     * @param {JingleSessionPC} session - the session which sends the media produced by the track.
     * @param {JitsiLocalTrack} track - the local track for which e2e encoder will be configured.
     * @private
     */
    _setupSenderE2EEForTrack(session: JingleSessionPC, track: JitsiLocalTrack) {
        if (!this.enabled) {
            return;
        }

        const pc = session.peerconnection;
        const sender = pc?.findSenderForTrack(track.track);

        if (sender) {
            this.e2eeCtx.handleSender(
                sender as CustomRTCRtpSender,
                track.getParticipantId(),
            );
        } else {
            console.warn(
                `E2E: Could not handle E2EE for ${track}: sender not found in ${pc}`,
            );
        }
    }

    /**
     * Setup E2EE on the sender that is created for the unmuted local video track.
     * @param {JitsiLocalTrack} track - the track for which muted status has changed.
     * @private
     */
    _trackMuteChanged(track: JitsiLocalTrack) {
        if (
            browser.doesVideoMuteByStreamRemove() &&
            track.isLocal() &&
            track.isVideoTrack() &&
            !track.isMuted()
        ) {
            for (const session of this.conference.getMediaSessions()) {
                this._setupSenderE2EEForTrack(session, track);
            }
        }
    }

    /**
     * Advances (using ratcheting) the current key when a new participant joins the conference.
     * Sends a session-init to a new participant if their ID is bigger than ID of this user.
     *
     * @private
     */
    async _onParticipantJoined(id: string) {
        this.logInfo(`Participant ${id} joined the conference.`);
        if (
            this._conferenceJoined &&
            this.enabled &&
            this._olmAdapter.isInitialized()
        ) {
            const participants = this.conference.getParticipants();
            const { olmKey, pqKey, index } =
                await this._olmAdapter.ratchetMyKeys();
            this.setKey(olmKey, pqKey, index);
            for (const participant of participants) {
                const pId = participant.getId();
                if (this._olmAdapter.checkIfShouldRatchetParticipantKey(pId)) {
                    this.e2eeCtx.ratchetKeys(pId);
                }
            }
        }
    }

    /**
     * Rotates the current key when a participant leaves the conference.
     * @private
     */
    async _onParticipantLeft(id: string) {
        this.logInfo(`Participant ${id} left the conference.`);
        if (this.enabled && this._olmAdapter.isInitialized()) {
            this._olmAdapter.clearParticipantSession(id);
            await this.initSessions;
            this.e2eeCtx.cleanup(id);
            const { olmKey, pqKey, index } = this._olmAdapter.updateMyKeys();
            this.setKey(olmKey, pqKey, index);
            const participants = this.conference.getParticipants();
            for (const participant of participants) {
                const pId = participant.getId();
                const data =
                    await this._olmAdapter.checkIfShouldSendKeyInfoToParticipant(
                        pId,
                    );
                if (data) {
                    this._sendMessage(OLM_MESSAGE_TYPES.KEY_INFO, data, pId);
                }
            }
        }
    }

    async _onConferenceLeft() {
        const participants = this.conference.getParticipants();
        for (const participant of participants) {
            this._olmAdapter.clearParticipantSession(participant.getId());
        }
        this._olmAdapter.clearMySession();
    }

    async _onEndpointMessageReceived(participant: JitsiParticipant, payload) {
        try {
            if (
                payload[JITSI_MEET_MUC_TYPE] !== OLM_MESSAGE_TYPE ||
                !payload.olm
            ) {
                console.error("E2E: Invalid or missing olm payload");
                return;
            }
            if (!this._olmAdapter.isInitialized()) {
                throw new Error("Olm not initialized");
            }

            const msg = payload.olm;
            const pId = participant.getId();

            switch (msg.type) {
                case OLM_MESSAGE_TYPES.SESSION_INIT: {
                    const { otKey, publicKey, publicKyberKey, commitment } =
                        msg.data;
                    const { data, keyCommitment } =
                        await this._olmAdapter.createPQsessionInitMessage(
                            pId,
                            otKey,
                            publicKey,
                            publicKyberKey,
                            commitment,
                        );
                    this.e2eeCtx.setKeysCommitment(pId, keyCommitment);
                    this._sendMessage(
                        OLM_MESSAGE_TYPES.PQ_SESSION_INIT,
                        data,
                        pId,
                    );
                    break;
                }

                case OLM_MESSAGE_TYPES.PQ_SESSION_INIT: {
                    const {
                        encapsKyber,
                        publicKey,
                        publicKyberKey,
                        ciphertext,
                    } = msg.data;
                    const { data, keyCommitment } =
                        await this._olmAdapter.createPQsessionAckMessage(
                            pId,
                            encapsKyber,
                            publicKey,
                            publicKyberKey,
                            ciphertext,
                        );
                    this.e2eeCtx.setKeysCommitment(pId, keyCommitment);
                    this._sendMessage(
                        OLM_MESSAGE_TYPES.PQ_SESSION_ACK,
                        data,
                        pId,
                    );
                    break;
                }
                case OLM_MESSAGE_TYPES.PQ_SESSION_ACK: {
                    const { encapsKyber, ciphertext, pqCiphertext } = msg.data;

                    const { data, key } =
                        await this._olmAdapter.createSessionAckMessage(
                            pId,
                            encapsKyber,
                            ciphertext,
                            pqCiphertext,
                        );
                    this.updateParticipantKey(pId, key);
                    this._sendMessage(OLM_MESSAGE_TYPES.SESSION_ACK, data, pId);
                    break;
                }
                case OLM_MESSAGE_TYPES.SESSION_ACK: {
                    const { ciphertext, pqCiphertext } = msg.data;

                    const { data, key } =
                        await this._olmAdapter.createSessionDoneMessage(
                            pId,
                            ciphertext,
                            pqCiphertext,
                        );
                    this.updateParticipantKey(pId, key);
                    this._sendMessage(OLM_MESSAGE_TYPES.SESSION_DONE, "", pId);
                    if (data) {
                        this.logInfo(
                            `Keys changes during session-init, sending new keys to ${pId}.`,
                        );
                        this._sendMessage(
                            OLM_MESSAGE_TYPES.KEY_INFO,
                            data,
                            pId,
                        );
                    }
                    const requestPromise = this._reqs.get(pId);
                    if (requestPromise) {
                        requestPromise.resolve();
                        this._reqs.delete(pId);
                    } else
                        console.warn(
                            `E2E: Session with ${pId} was established after reaching time out.`,
                        );
                    break;
                }
                case OLM_MESSAGE_TYPES.ERROR: {
                    console.error(msg.data.error);
                    break;
                }
                case OLM_MESSAGE_TYPES.SESSION_DONE: {
                    const data =
                        await this._olmAdapter.processSessionDoneMessage(pId);
                    if (data) {
                        this.logInfo(
                            `Keys changes during session-init, sending new keys to ${pId}.`,
                        );
                        this._sendMessage(
                            OLM_MESSAGE_TYPES.KEY_INFO,
                            data,
                            pId,
                        );
                    }
                    this.logInfo(
                        `Participant ${pId} established E2E channel with us.`,
                    );
                    break;
                }
                case OLM_MESSAGE_TYPES.KEY_INFO: {
                    const { ciphertext, pqCiphertext } = msg.data;
                    const key = await this._olmAdapter.processKeyInfoMessage(
                        pId,
                        ciphertext,
                        pqCiphertext,
                    );
                    this.updateParticipantKey(pId, key);
                    break;
                }
            }
        } catch (error) {
            const data: SessionError = { error };
            console.error(`E2E: Error processing message: ${error}`);
            this._sendMessage(
                OLM_MESSAGE_TYPES.ERROR,
                data,
                participant.getId(),
            );
        }
    }

    /**
     * Set the keys of the current participant.
     * @param {Uint8Array} olmKey - The olm key.
     * @param {Uint8Array} pqKey - The pq key.
     * @param {number} index - The keys index.
     * @private
     */
    setKey(olmKey: Uint8Array, pqKey: Uint8Array, index: number) {
        this.e2eeCtx.setKey(this.conference.myUserId(), olmKey, pqKey, index);
    }

    /**
     * Updates a participant's key.
     *
     * @param {string} id - The participant ID.
     * @param {Uint8Array} olmKey - The new olm key of the participant.
     * @param {Uint8Array} pqKey - The new pq key of the participant.
     * @param {number} index - The new key's index.
     * @private
     */
    updateParticipantKey(id: string, key: MediaKey) {
        this.e2eeCtx.setKey(id, key.olmKey, key.pqKey, key.index);
    }

    /**
     * Internal helper to send the given object to the given participant ID.
     * This function merely exists so the transport can be easily swapped.
     * Currently messages are transmitted via XMPP MUC private messages.
     *
     * @param {object} data - The data that will be sent to the target participant.
     * @param {string} participantId - ID of the target participant.
     */
    _sendMessage(
        type: MessageType,
        data: ReplyMessage | "",
        participantId: string,
    ) {
        const msg = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type,
                data,
            },
        };
        this.conference.sendMessage(msg, participantId);
    }

    logInfo(message: string) {
        console.info(`E2E: ${message}`);
    }
}
