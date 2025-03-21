/// <reference types="node" />

import { getLogger } from "@jitsi/logger";
import browser from "../browser";
import JitsiLocalTrack from "../RTC/JitsiLocalTrack";
import JingleSessionPC from "../xmpp/JingleSessionPC";
import TraceablePeerConnection from "../RTC/TraceablePeerConnection";
import { CustomRTCRtpReceiver, CustomRTCRtpSender } from "./E2EEContext";

import * as JitsiConferenceEvents from "../../JitsiConferenceEvents";

import Listenable from "../util/Listenable";
import { OlmAdapter } from "./OlmAdapter";
import JitsiConference from "../../JitsiConference";
import E2EEContext from "./E2EEContext";
import RTCEvents from "../../service/RTC/RTCEvents";
import { generateEmojiSas } from "./SAS";

const logger = getLogger(__filename);

/**
 * This module integrates {@link E2EEContext} with {@link OlmAdapter} in order to distribute the keys for encryption.
 */
export class ManagedKeyHandler extends Listenable {
    conference: JitsiConference;
    e2eeCtx: E2EEContext;
    enabled: boolean;
    init: any;
    _olmAdapter: OlmAdapter;
    private _conferenceJoined: boolean;

    /**
     * Build a new AutomaticKeyHandler instance, which will be used in a given conference.
     */
    constructor(conference: JitsiConference) {
        super();
        this.conference = conference;
        this.e2eeCtx = new E2EEContext();

        this.enabled = false;

        this.conference.on(
            JitsiConferenceEvents.USER_JOINED,
            this._onParticipantJoined.bind(this),
        );
        this.conference.on(
            JitsiConferenceEvents.USER_LEFT,
            this._onParticipantLeft.bind(this),
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

        this._olmAdapter = new OlmAdapter(conference);

        // Olm signalling events.
        this._olmAdapter.on(
            OlmAdapter.events.PARTICIPANT_KEY_UPDATED,
            this._onParticipantKeyUpdated.bind(this),
        );

        this._olmAdapter.on(
            OlmAdapter.events.PARTICIPANT_KEYS_COMMITMENT,
            this._onParticipantKeysCommitted.bind(this),
        );

        this._olmAdapter.on(
            OlmAdapter.events.PARTICIPANT_KEY_RATCHET,
            this._onParticipantKeyRatchet.bind(this),
        );

        this.e2eeCtx.on("sasUpdated", (sasStr: string) => {
            (async () => {
                const sas = await generateEmojiSas(sasStr);
                console.log(`E2E: Generated SAS: ${sas}`);
                this.conference.eventEmitter.emit(
                    JitsiConferenceEvents.E2EE_SAS_AVAILABLE,
                    sas,
                );
            })();
        });
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

        if (enabled) {
            logger.info("E2E: Enabling e2ee");

            this.enabled = true;
            this.init = this._olmAdapter.initSessions();
            await this.init; 
        }

        if (!enabled) {
            logger.info("E2E: Disabling e2ee");
            this.enabled = false;
            this.e2eeCtx.cleanupAll();
            this._olmAdapter.clearAllParticipantsSessions();
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
            logger.warn(
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
        const sender = pc && pc.findSenderForTrack(track.track);

        if (sender) {
            this.e2eeCtx.handleSender(
                sender as CustomRTCRtpSender,
                track.getParticipantId(),
            );
        } else {
            logger.warn(
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
        logger.info(`E2E: A new participant ${id} joined the conference`);
        if (this._conferenceJoined && this.enabled) {
            await this.init; 
            await this._olmAdapter._ratchetKeyImpl();
        }
    }

    /**
     * Rotates the current key when a participant leaves the conference.
     * @private
     */
   async _onParticipantLeft(id: string) {
        logger.info(`E2E: Participant ${id} left the conference.`);
        this.e2eeCtx.cleanup(id);

        if (this.enabled) {
            await this.init; 
            this._olmAdapter._rotateKeyImpl();
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
    _onParticipantKeyUpdated(
        id: string,
        olmKey: Uint8Array,
        pqKey: Uint8Array,
        index: number,
    ) {
        this.e2eeCtx.setKey(id, olmKey, pqKey, index);
    }

    /**
     * Updates a participant's key.
     *
     * @param {string} id - The participant ID.
     * @param {Uint8Array} commitment - The commitment to participant's identity keys.
     * @private
     */
    _onParticipantKeysCommitted(id: string, commitment: Uint8Array) {
        this.e2eeCtx.setKeysCommitment(id, commitment);
    }

    /**
     * Ratchets a participant's key.
     *
     * @param {string} id - The participant ID.
     * @private
     */
    _onParticipantKeyRatchet(id: string) {
        this.e2eeCtx.ratchetKeys(id);
    }
}
