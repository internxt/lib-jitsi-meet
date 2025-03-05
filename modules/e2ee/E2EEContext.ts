/* global RTCRtpScriptTransform */
import { getLogger } from "@jitsi/logger";
import { generateEmojiSas } from "./SAS";

// Extend the RTCRtpReceiver interface due to lack of support of streams
interface CustomRTCRtpReceiver extends RTCRtpReceiver {
    createEncodedStreams?: () => {
        readable: ReadableStream;
        writable: WritableStream;
    };
    transform: RTCRtpScriptTransform;
}

interface CustomRTCRtpSender extends RTCRtpSender {
    createEncodedStreams?: () => {
        readable: ReadableStream;
        writable: WritableStream;
    };
    transform: RTCRtpScriptTransform;
}

const logger = getLogger(__filename);

// Flag to set on senders / receivers to avoid setting up the encryption transform
// more than once.
const kJitsiE2EE = Symbol("kJitsiE2EE");

/**
 * Context encapsulating the cryptography bits required for E2EE.
 * This uses the WebRTC Insertable Streams API which is explained in
 *   https://github.com/alvestrand/webrtc-media-streams/blob/master/explainer.md
 * that provides access to the encoded frames and allows them to be transformed.
 *
 * The encoded frame format is explained below in the _encodeFunction method.
 * High level design goals were:
 * - do not require changes to existing SFUs and retain (VP8) metadata.
 * - allow the SFU to rewrite SSRCs, timestamp, pictureId.
 * - allow for the key to be rotated frequently.
 */
export default class E2EEcontext {
    private _worker: Worker;
    /**
     * Build a new E2EE context instance, which will be used in a given conference.
     */
    constructor() {
        // Determine the URL for the worker script. Relative URLs are relative to
        // the entry point, not the script that launches the worker.
        let baseUrl = "";
        const ljm = document.querySelector<HTMLImageElement>(
            'script[src*="lib-jitsi-meet"]',
        ); // as HTMLImageElement;

        if (ljm) {
            const idx = ljm.src.lastIndexOf("/");

            baseUrl = `${ljm.src.substring(0, idx)}/`;
        }

        let workerUrl = `${baseUrl}lib-jitsi-meet.e2ee-worker.js`;

        // If there is no baseUrl then we create the worker in a normal way
        // as you cant load scripts inside blobs from relative paths.
        // See: https://www.html5rocks.com/en/tutorials/workers/basics/#toc-inlineworkers-loadingscripts
        if (baseUrl && baseUrl !== "/") {
            // Initialize the E2EE worker. In order to avoid CORS issues, start the worker and have it
            // synchronously load the JS.
            const workerBlob = new Blob([`importScripts("${workerUrl}");`], {
                type: "application/javascript",
            });

            workerUrl = window.URL.createObjectURL(workerBlob);
        }

        this._worker = new Worker(workerUrl, { name: "E2EE Worker" });

        this._worker.onerror = (e) => logger.error(e);

        this._worker.onmessage = this.updateSAS.bind(this);
    }

    /**
     * Cleans up all state associated with the given participant. This is needed when a
     * participant leaves the current conference.
     *
     * @param {string} participantId - The participant that just left.
     */
    cleanup(participantId: string) {
        this._worker.postMessage({
            operation: "cleanup",
            participantId,
        });
    }

    /**
     * Cleans up all state associated with all participants in the conference. This is needed when disabling e2ee.
     *
     */
    cleanupAll() {
        this._worker.postMessage({
            operation: "cleanupAll",
        });
    }

    /**
     * Handles the given {@code RTCRtpReceiver} by creating a {@code TransformStream} which will inject
     * a frame decoder.
     *
     * @param {RTCRtpReceiver} receiver - The receiver which will get the decoding function injected.
     * @param {string} kind - The kind of track this receiver belongs to.
     * @param {string} participantId - The participant id that this receiver belongs to.
     */
    handleReceiver(receiver: CustomRTCRtpReceiver, participantId: string) {
        if (receiver[kJitsiE2EE]) {
            return;
        }
        receiver[kJitsiE2EE] = true;

        if (window.RTCRtpScriptTransform) {
            const options = {
                operation: "decode",
                participantId,
            };

            receiver.transform = new RTCRtpScriptTransform(
                this._worker,
                options,
            );
        } else {
            const receiverStreams = receiver.createEncodedStreams();

            this._worker.postMessage(
                {
                    operation: "decode",
                    readableStream: receiverStreams.readable,
                    writableStream: receiverStreams.writable,
                    participantId,
                },
                [receiverStreams.readable, receiverStreams.writable],
            );
        }
    }

    /**
     * Handles the given {@code RTCRtpSender} by creating a {@code TransformStream} which will inject
     * a frame encoder.
     *
     * @param {RTCRtpSender} sender - The sender which will get the encoding function injected.
     * @param {string} kind - The kind of track this sender belongs to.
     * @param {string} participantId - The participant id that this sender belongs to.
     */
    handleSender(sender: CustomRTCRtpSender, participantId: string) {
        if (sender[kJitsiE2EE]) {
            return;
        }
        sender[kJitsiE2EE] = true;

        if (window.RTCRtpScriptTransform) {
            const options = {
                operation: "encode",
                participantId,
            };

            sender.transform = new RTCRtpScriptTransform(this._worker, options);
        } else {
            const senderStreams = sender.createEncodedStreams();

            this._worker.postMessage(
                {
                    operation: "encode",
                    readableStream: senderStreams.readable,
                    writableStream: senderStreams.writable,
                    participantId,
                },
                [senderStreams.readable, senderStreams.writable],
            );
        }
    }

    /**
     * Set the E2EE key for the specified participant.
     *
     * @param {string} participantId - The ID of the participant who's key we are setting.
     * @param {Uint8Array} olmKey - The olm key for the given participant.
     * @param {Uint8Array} pqKey - The pq key for the given participant.
     * @param {number} keyIndex - The key index.
     */
    setKey(
        participantId: string,
        olmKey: Uint8Array,
        pqKey: Uint8Array,
        index: number,
    ) {
        this._worker.postMessage({
            operation: "setKey",
            olmKey,
            pqKey,
            index,
            participantId,
        });
    }

    /**
     * Set the commitment to keys for the specified participant.
     *
     * @param {string} participantId - The ID of the participant who's key we are setting.
     * @param {Uint8Array} commitment - The commitment to the participant's keys.
     */
    setKeyCommitment(participantId: string, commitment: Uint8Array) {
        this._worker.postMessage({
            operation: "setKeyCommitment",
            commitment,
            participantId,
        });
    }

    /**
     * Request to ratchet keys for the specified participant.
     *
     * @param {string} participantId - The ID of the participant
     */
    ratchetKeys(participantId: string) {
        this._worker.postMessage({
            operation: "ratchetKeys",
            participantId,
        });
    }

    /**
     * Request to ratchet keys for the specified participant.
     *
     * @param {string} participantId - The ID of the participant
     */
    setDecryptionFlag(participantId: string, decryptionFlag: boolean) {
        this._worker.postMessage({
            operation: "setDecryptionFlag",
            participantId,
            decryptionFlag,
        });
    }

    /**
     * Update SAS string.
     */
    private updateSAS(event: MessageEvent) {
        if (event.data.operation === "updateSAS") {
            const sasBytes = event.data.sas;
            const sas = generateEmojiSas(sasBytes);
            logger.info(`E2E: worker response: ${sas}`);
        }
    }
}
