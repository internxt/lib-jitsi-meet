/// <reference types="node" />

import { getLogger } from "@jitsi/logger";
import browser from "../browser";

import * as JitsiConferenceEvents from "../../JitsiConferenceEvents";

import Listenable from "../util/Listenable";
import { OlmAdapter } from "./OlmAdapter";
import JitsiConference from "../../JitsiConference";
import E2EEContext from "./E2EEContext";
import RTCEvents from "../../service/RTC/RTCEvents";

const logger = getLogger(__filename);

/**
 * This module integrates {@link E2EEContext} with {@link OlmAdapter} in order to distribute the keys for encryption.
 */
export class ManagedKeyHandler extends Listenable {
    conference: JitsiConference;
    e2eeCtx: E2EEContext;
    enabled: boolean;
    _olmAdapter: OlmAdapter;
    private _conferenceJoined: boolean;

    /**
     * Build a new AutomaticKeyHandler instance, which will be used in a given conference.
     */
    constructor(conference) {
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
            (track) => track.isLocal() && this._onLocalTrackAdded(track),
        );
        this.conference.rtc.on(RTCEvents.REMOTE_TRACK_ADDED, (track, tpc) =>
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
            OlmAdapter.events.PARTICIPANT_KEY_RATCHET,
            this._onParticipantKeyRatchet.bind(this),
        );

        this._olmAdapter.on(
            OlmAdapter.events.PARTICIPANT_SAS_READY,
            this._onParticipantSasReady.bind(this),
        );

        this._olmAdapter.on(
            OlmAdapter.events.PARTICIPANT_SAS_AVAILABLE,
            this._onParticipantSasAvailable.bind(this),
        );

        this._olmAdapter.on(
            OlmAdapter.events.PARTICIPANT_VERIFICATION_COMPLETED,
            this._onParticipantVerificationCompleted.bind(this),
        );
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
    async setEnabled(enabled) {
        if (enabled === this.enabled) {
            return;
        }

        if (enabled) {
            logger.info("E2E: Enabling e2ee");

            this.enabled = true;
            await this._olmAdapter.initSessions();

            const { olmKey, pqKey, index } = this._olmAdapter.getCurrentKeys();
            this.e2eeCtx.setKey(
                this.conference.myUserId(),
                olmKey,
                pqKey,
                index,
            );

            this.conference.setLocalParticipantProperty("e2ee.enabled", true);
            this.conference._restartMediaSessions();
        }

        if (!enabled) {
            logger.info("E2E: Disabling e2ee");
            this.enabled = false;
            this.e2eeCtx.cleanupAll();
        }
    }

    /**
     * Setup E2EE on the new track that has been added to the conference, apply it on all the open peerconnections.
     * @param {JitsiLocalTrack} track - the new track that's being added to the conference.
     * @private
     */
    _onLocalTrackAdded(track) {
        for (const session of this.conference.getMediaSessions()) {
            this._setupSenderE2EEForTrack(session, track);
        }
    }

    /**
     * Setups E2E encryption for the new session.
     * @param {JingleSessionPC} session - the new media session.
     * @private
     */
    _onMediaSessionStarted(session) {
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
    _setupReceiverE2EEForTrack(tpc, track) {
        if (!this.enabled) {
            return;
        }

        const receiver = tpc.findReceiverForTrack(track.track);

        if (receiver) {
            this.e2eeCtx.handleReceiver(
                receiver,
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
    _setupSenderE2EEForTrack(session, track) {
        if (!this.enabled) {
            return;
        }

        const pc = session.peerconnection;
        const sender = pc && pc.findSenderForTrack(track.track);

        if (sender) {
            this.e2eeCtx.handleSender(
                sender,
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
    _trackMuteChanged(track) {
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
     * Returns the sasVerficiation object.
     *
     * @returns {Object}
     */
    get sasVerification() {
        return this._olmAdapter;
    }

    /**
     * Advances (using ratcheting) the current key when a new participant joins the conference.
     * @private
     */
    _onParticipantJoined() {
        logger.info(
            `E2E: A new participant joined the conference`,
        );
        if (this._conferenceJoined && this.enabled) {
            this._ratchetKeyImpl();
        }
    }

    /**
     * Rotates the current key when a participant leaves the conference.
     * @private
     */
    _onParticipantLeft(id: string) {
        logger.info(`E2E: Participant ${id} left the conference.`);
        this.e2eeCtx.cleanup(id);

        if (this.enabled) {
            this._rotateKeyImpl();
        }
    }

    /**
     * Rotates the local key. Rotating the key implies creating a new one, then distributing it
     * to all participants and once they all received it, start using it.
     *
     * @private
     */
    async _rotateKeyImpl() {
        try {
            logger.info("E2E: Rotating my keys");
            await this._olmAdapter._rotateKeyImpl();
            const { olmKey, pqKey, index } = this._olmAdapter.getCurrentKeys();
            this.setKey(olmKey, pqKey, index);
        } catch (error){
            logger.error(`E2E: Key rotation failed: ${error}`);
        }
    }

    setKey(olmKey: Uint8Array, pqKey: Uint8Array, index: number) {
        this.e2eeCtx.setKey(this.conference.myUserId(), olmKey, pqKey, index);
    }
    /**
     * Advances the current key by using ratcheting.
     *
     * @private
     */
    async _ratchetKeyImpl() {
        try {
            logger.info("Ratchetting my keys.");
            await this._olmAdapter._ratchetKeyImpl();
            const { olmKey, pqKey, index } = this._olmAdapter.getCurrentKeys();
            this.setKey(olmKey, pqKey, index);
        } catch (error) {
            logger.error(`E2E: Key ratcheting failed: ${error}`);
        }
        
    }

    /**
     * Handles an update in a participant's key.
     *
     * @param {string} id - The participant ID.
     * @param {Uint8Array | boolean} key - The new key for the participant.
     * @param {Number} index - The new key's index.
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
     * Handles an update in a participant's key.
     *
     * @param {string} id - The participant ID.
     * @param {Uint8Array | boolean} key - The new key for the participant.
     * @param {Number} index - The new key's index.
     * @private
     */
    _onParticipantKeyRatchet(
        id: string,
    ) {
        logger.info(`E2E: Ratcheting keys of participant ${id}`);
        this.e2eeCtx.ratchetKeys(id);
    }

    /**
     * Handles the SAS ready event.
     *
     * @param {string} pId - The participant ID.
     * @param {Uint8Array} sas - The bytes from sas.generate_bytes..
     * @private
     */
    _onParticipantSasReady(pId: string, sas: Uint8Array) {
        this.conference.eventEmitter.emit(
            JitsiConferenceEvents.E2EE_VERIFICATION_READY,
            pId,
            sas,
        );
    }

    /**
     * Handles the sas available event.
     *
     * @param {string} pId - The participant ID.
     * @private
     */
    _onParticipantSasAvailable(pId: string) {
        this.conference.eventEmitter.emit(
            JitsiConferenceEvents.E2EE_VERIFICATION_AVAILABLE,
            pId,
        );
    }

    /**
     * Handles the SAS completed event.
     *
     * @param {string} pId - The participant ID.
     * @param {boolean} success - Wheter the verification was succesfull.
     * @private
     */
    _onParticipantVerificationCompleted(
        pId: string,
        success: boolean,
        message,
    ) {
        this.conference.eventEmitter.emit(
            JitsiConferenceEvents.E2EE_VERIFICATION_COMPLETED,
            pId,
            success,
            message,
        );
    }
}
