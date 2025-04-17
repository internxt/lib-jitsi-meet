import {
    deriveEncryptionKey,
    ratchetKey,
    encryptData,
    decryptData,
    hashKeysOfParticipant,
    logError,
    logInfo,
} from "./crypto-workers";
import { KEYRING_SIZE, VIDEO_UNENCRYPTED_BYTES, IV_LENGTH } from "./Constants";

let printEncStart = true;

/**
 * Per-participant context holding the cryptographic keys
 */
export class Context {
    private readonly id: string;
    private encryptionKey: CryptoKey;
    private olmKey: Uint8Array;
    private pqKey: Uint8Array;
    private index: number;
    private hash: string;
    private commitment: string;

    constructor(id: string) {
        this.encryptionKey = null as any;
        this.olmKey = new Uint8Array();
        this.pqKey = new Uint8Array();
        this.id = id;
        this.commitment = "";
        this.hash = "";
        this.index = -1;
    }

    async ratchetKeys() {
        const currentIndex = this.index;
        if (currentIndex >= 0) {
            const newMaterialOlm = await ratchetKey(this.olmKey);
            const newMaterialPQ = await ratchetKey(this.pqKey);
            logInfo(`Ratchet keys of participant ${this.id}`);
            this.setKey(newMaterialOlm, newMaterialPQ, currentIndex + 1);
        }
    }

    async setKeyCommitment(commitment: string) {
        this.commitment = commitment;
    }

    getHash() {
        return this.hash;
    }

    /**
     * Derives the encryption key and sets participant key.
     * @param {Uint8Array} olmKey The olm key.
     * @param {Uint8Array} pqKey The pq key.
     * @param {number} index The keys index.
     */
    async setKey(olmKey: Uint8Array, pqKey: Uint8Array, index: number) {
        this.olmKey = olmKey;
        this.pqKey = pqKey;
        this.encryptionKey = await deriveEncryptionKey(this.olmKey, pqKey);
        this.index = index % KEYRING_SIZE;
        this.hash = await hashKeysOfParticipant(
            this.id,
            this.olmKey,
            this.pqKey,
            this.index,
            this.commitment,
        );
        logInfo(
            `Set keys for ${this.id}, index is ${this.index} and hash is ${this.hash}`,
        );
    }

    /**
     * Function that will be injected in a stream and will encrypt the given encoded frames.
     *
     * @param {RTCEncodedVideoFrame|RTCEncodedAudioFrame} encodedFrame - Encoded video frame.
     * @param {TransformStreamDefaultController} controller - TransportStreamController.
     *
     */
    async encodeFunction(
        encodedFrame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
        controller: TransformStreamDefaultController,
    ) {
        if (this.index >= 0) {
            const encryptedFrame = await this._encryptFrame(encodedFrame);

            if (encryptedFrame) {
                controller.enqueue(encryptedFrame);
            }
        }
    }

    /**
     * Function that will encrypt the given encoded frame.
     *
     * @param {RTCEncodedVideoFrame|RTCEncodedAudioFrame} encodedFrame - Encoded video frame.
     * @returns {Promise<RTCEncodedVideoFrame|RTCEncodedAudioFrame>} - The encrypted frame.
     * @private
     * The VP8 payload descriptor described in
     * https://tools.ietf.org/html/rfc7741#section-4.2
     * is part of the RTP packet and not part of the frame and is not controllable by us.
     * This is fine as the SFU keeps having access to it for routing.
     *
     * The encrypted frame is formed as follows:
     * 1) Leave the first (10, 3, 1) bytes unencrypted, depending on the frame type and kind.
     * 2) Form the GCM IV for the frame as described above.
     * 3) Encrypt the rest of the frame using AES-GCM.
     * 4) Allocate space for the encrypted frame.
     * 5) Copy the unencrypted bytes to the start of the encrypted frame.
     * 6) Append the ciphertext to the encrypted frame.
     * 7) Append the IV.
     * 8) Append a single byte for the key identifier.
     * 9) Enqueue the encrypted frame for sending.
     */
    async _encryptFrame(
        encodedFrame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
    ) {
        const key: CryptoKey = this.encryptionKey;
        const keyIndex = this.index;
        try {
            const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
            // Thіs is not encrypted and contains the VP8 payload descriptor or the Opus TOC byte.
            let unencrypted_bytes_number: number = 1; // for audio frame
            if (encodedFrame instanceof RTCEncodedVideoFrame)
                unencrypted_bytes_number =
                    VIDEO_UNENCRYPTED_BYTES[
                        encodedFrame.type as keyof typeof VIDEO_UNENCRYPTED_BYTES
                    ];
            const frameHeader = new Uint8Array(
                encodedFrame.data,
                0,
                unencrypted_bytes_number,
            );

            // Frame trailer contains the R|IV_LENGTH and key index
            const frameTrailer = new Uint8Array(2);

            frameTrailer[0] = IV_LENGTH;
            frameTrailer[1] = keyIndex;

            // Construct frame trailer. Similar to the frame header described in
            // https://tools.ietf.org/html/draft-omara-sframe-00#section-4.2
            // but we put it at the end.
            //
            // ---------+-------------------------+-+---------+----
            // payload  |IV...(length = IV_LENGTH)|R|IV_LENGTH|KID |
            // ---------+-------------------------+-+---------+----
            const data: Uint8Array = new Uint8Array(
                encodedFrame.data,
                unencrypted_bytes_number,
            );
            const additionalData = new Uint8Array(
                encodedFrame.data,
                0,
                frameHeader.byteLength,
            );
            const cipherText = await encryptData(iv, additionalData, key, data);

            const newData = new ArrayBuffer(
                frameHeader.byteLength +
                    cipherText.byteLength +
                    iv.byteLength +
                    frameTrailer.byteLength,
            );
            const newUint8 = new Uint8Array(newData);

            newUint8.set(frameHeader); // copy first bytes.
            newUint8.set(new Uint8Array(cipherText), frameHeader.byteLength); // add ciphertext.
            newUint8.set(
                new Uint8Array(iv),
                frameHeader.byteLength + cipherText.byteLength,
            ); // append IV.
            newUint8.set(
                frameTrailer,
                frameHeader.byteLength + cipherText.byteLength + iv.byteLength,
            ); // append frame trailer.
            encodedFrame.data = newData;
            if (printEncStart) {
                logInfo("Started encrypting my frames!");
                printEncStart = false;
            }
            return encodedFrame;
        } catch (e) {
            // TODO: surface this to the app.
            logError(`Encryption failed: ${e}`);

            // We are not enqueuing the frame here on purpose.
        }
    }

    /**
     * Function that will be injected in a stream and will decrypt the given encoded frames.
     *
     * @param {RTCEncodedVideoFrame|RTCEncodedAudioFrame} encodedFrame - Encoded video frame.
     * @param {TransformStreamDefaultController} controller - TransportStreamController.
     */
    async decodeFunction(
        encodedFrame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
        controller: TransformStreamDefaultController,
    ) {
        const data = new Uint8Array(encodedFrame.data);
        const keyIndex = data[encodedFrame.data.byteLength - 1];
        if (keyIndex === this.index) {
            const decodedFrame = await this._decryptFrame(encodedFrame);

            if (decodedFrame) {
                controller.enqueue(decodedFrame);
            }
        }
    }

    /**
     * Function that will decrypt the given encoded frame.
     *
     * @param {RTCEncodedVideoFrame|RTCEncodedAudioFrame} encodedFrame - Encoded video frame.
     * @returns {Promise<RTCEncodedVideoFrame|RTCEncodedAudioFrame>} - The decrypted frame.
     * @private
     */
    async _decryptFrame(
        encodedFrame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
    ) {
        const encryptionKey = this.encryptionKey;
        try {
            let ind = 1;
            if (encodedFrame instanceof RTCEncodedVideoFrame)
                ind =
                    VIDEO_UNENCRYPTED_BYTES[
                        encodedFrame.type as keyof typeof VIDEO_UNENCRYPTED_BYTES
                    ];
            const frameHeader = new Uint8Array(encodedFrame.data, 0, ind);
            const frameTrailer = new Uint8Array(
                encodedFrame.data,
                encodedFrame.data.byteLength - 2,
                2,
            );

            const ivLength = frameTrailer[0];
            const iv = new Uint8Array(
                encodedFrame.data,
                encodedFrame.data.byteLength -
                    ivLength -
                    frameTrailer.byteLength,
                ivLength,
            );

            const cipherTextStart = frameHeader.byteLength;
            const cipherTextLength =
                encodedFrame.data.byteLength -
                (frameHeader.byteLength + ivLength + frameTrailer.byteLength);

            const additionalData = new Uint8Array(
                encodedFrame.data,
                0,
                frameHeader.byteLength,
            );
            const data = new Uint8Array(
                encodedFrame.data,
                cipherTextStart,
                cipherTextLength,
            );
            const plainText = await decryptData(
                iv,
                additionalData,
                encryptionKey,
                data,
            );

            const newData = new ArrayBuffer(
                frameHeader.byteLength + plainText.byteLength,
            );
            const newUint8 = new Uint8Array(newData);

            newUint8.set(
                new Uint8Array(encodedFrame.data, 0, frameHeader.byteLength),
            );
            newUint8.set(new Uint8Array(plainText), frameHeader.byteLength);

            encodedFrame.data = newData;

            return encodedFrame;
        } catch (error) {
            logError(`Decryption of a frame from ${this.id} failed: ${error}`);
        }
    }
}
