import {
    deriveEncryptionKey,
    ratchetKey,
    encryptData,
    decryptData,
    computeHash,
} from "./crypto-workers";

// We use a ringbuffer of keys so we can change them and still decode packets that were
// encrypted with an old key. We use a size of 16 which corresponds to the four bits
// in the frame trailer.
const KEYRING_SIZE = 16;

// We copy the first bytes of the VP8 payload unencrypted.
// For keyframes this is 10 bytes, for non-keyframes (delta) 3. See
//   https://tools.ietf.org/html/rfc6386#section-9.1
// This allows the bridge to continue detecting keyframes (only one byte needed in the JVB)
// and is also a bit easier for the VP8 decoder (i.e. it generates funny garbage pictures
// instead of being unable to decode).
// This is a bit for show and we might want to reduce to 1 unconditionally in the final version.
//
// For audio (where frame.type is not set) we do not encrypt the opus TOC byte:
//   https://tools.ietf.org/html/rfc6716#section-3.1
const VIDEO_UNENCRYPTED_BYTES = {
    key: 10,
    delta: 3,
};
let printEncStart = true;

/* We use a 96 bit IV for AES GCM. This is signalled in plain together with the
 packet. See https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams */
const IV_LENGTH = 12;

type KeyMaterial = {
    encryptionKey: CryptoKey;
    materialOlm: Uint8Array;
    materialPQ: Uint8Array;
};

/**
 * Per-participant context holding the cryptographic keys and
 * encode/decode functions
 */
export class Context {
    private _participantId: string;
    private _cryptoKeyRing: KeyMaterial[];
    private _currentKeyIndex: number;
    private _sendCounts: Map<number, number>;
    private _hash: string;
    private _keyCommtiment: string;
    /**
     * @param {string} id
     */
    constructor(id: string) {
        this._cryptoKeyRing = new Array(KEYRING_SIZE);
        this._sendCounts = new Map();
        this._participantId = id;
        this._keyCommtiment = "";
        this._hash = "";
        this._currentKeyIndex = -1;
    }

    /**
     * Ratchet keys.
     * @private
     */
    async ratchetKeys() {
        const currentIndex = this._currentKeyIndex;
        console.info(
            `E2E: Attempt to ratchet keys of participant ${this._participantId}, index is ${currentIndex}`,
        );
        if (currentIndex >= 0) {
            const { materialOlm, materialPQ } =
                this._cryptoKeyRing[currentIndex];
            const newMaterialOlm = await ratchetKey(materialOlm);
            const newMaterialPQ = await ratchetKey(materialPQ);
            console.info(
                `E2E: Ratchet keys of participant ${this._participantId}`,
            );
            this.setKey(newMaterialOlm, newMaterialPQ, currentIndex + 1);
        }
    }

    /**
     * Sets key commitment
     * @private
     */
    async setKeyCommitment(commitment: string) {
        this._keyCommtiment = commitment;
        console.info(
            `E2E: Set commitment to idenity keys of a participant ${this._participantId}`,
        );
        const currentIndex = this._currentKeyIndex;
        if (currentIndex >= 0 && !this._hash) {
            const { materialOlm, materialPQ } =
                this._cryptoKeyRing[currentIndex];
            this._hash = await computeHash(
                materialOlm,
                materialPQ,
                this._keyCommtiment,
                this._currentKeyIndex,
            );
        }
    }

    /**
     * Returns the key hash.
     */
    getHash() {
        return this._hash;
    }

    /**
     * Derives the encryption key and sets participant key.
     * @param {Uint8Array} olmKey The olm key.
     * @param {Uint8Array} pqKey The pq key.
     * @param {number} index The keys index.
     */
    async setKey(olmKey: Uint8Array, pqKey: Uint8Array, index: number) {
        const encryptionKey = await deriveEncryptionKey(olmKey, pqKey);
        const newKey: KeyMaterial = {
            materialOlm: olmKey,
            materialPQ: pqKey,
            encryptionKey,
        };
        this._currentKeyIndex = index % KEYRING_SIZE;
        this._cryptoKeyRing[this._currentKeyIndex] = newKey;
        if (this._keyCommtiment)
            this._hash = await computeHash(
                olmKey,
                pqKey,
                this._keyCommtiment,
                this._currentKeyIndex,
            );
        console.info(`E2E: Set keys for ${this._participantId}`);
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
        const keyIndex = this._currentKeyIndex;
        if (this._cryptoKeyRing[keyIndex]) {
            const encryptedFrame = await this._encryptFrame(
                encodedFrame,
                keyIndex,
            );

            if (encryptedFrame) {
                controller.enqueue(encryptedFrame);
            }
        }
    }

    /**
     * Function that will encrypt the given encoded frame.
     *
     * @param {RTCEncodedVideoFrame|RTCEncodedAudioFrame} encodedFrame - Encoded video frame.
     * @param {number} keyIndex - The index of the encryption key in _cryptoKeyRing array.
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
        keyIndex: number,
    ) {
        const key: CryptoKey = this._cryptoKeyRing[keyIndex].encryptionKey;
        try {
            const iv = this._makeIV(
                encodedFrame.getMetadata().synchronizationSource ?? 0,
                encodedFrame.timestamp,
            );
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
                console.info("E2E: Start encryption of my frames!");
                printEncStart = false;
            }

            return encodedFrame;
        } catch (e) {
            // TODO: surface this to the app.
            console.error(`E2E: Encryption failed: ${e}`);
            printEncStart = true;

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
        if (this._cryptoKeyRing[keyIndex]) {
            const decodedFrame = await this._decryptFrame(
                encodedFrame,
                keyIndex,
            );

            if (decodedFrame) {
                controller.enqueue(decodedFrame);
            }
        }
    }

    /**
     * Function that will decrypt the given encoded frame.
     *
     * @param {RTCEncodedVideoFrame|RTCEncodedAudioFrame} encodedFrame - Encoded video frame.
     * @param {number} keyIndex - The index of the decryption key in _cryptoKeyRing array.
     * @returns {Promise<RTCEncodedVideoFrame|RTCEncodedAudioFrame>} - The decrypted frame.
     * @private
     */
    async _decryptFrame(
        encodedFrame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
        keyIndex: number,
    ) {
        const { encryptionKey } = this._cryptoKeyRing[keyIndex];

        // Construct frame trailer. Similar to the frame header described in
        // https://tools.ietf.org/html/draft-omara-sframe-00#section-4.2
        // but we put it at the end.
        //
        // ---------+-------------------------+-+---------+----
        // payload  |IV...(length = IV_LENGTH)|R|IV_LENGTH|KID |
        // ---------+-------------------------+-+---------+----

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
            console.error(
                `E2E: Got error while decrypting frame from ${this._participantId}: ${error}`,
            );
        }
    }

    /**
     * Construct the IV used for AES-GCM and sent (in plain) with the packet similar to
     * https://tools.ietf.org/html/rfc7714#section-8.1
     * It concatenates
     * - the 32 bit synchronization source (SSRC) given on the encoded frame,
     * - the 32 bit rtp timestamp given on the encoded frame,
     * - a send counter that is specific to the SSRC. Starts at a random number.
     * The send counter is essentially the pictureId but we currently have to implement this ourselves.
     * There is no XOR with a salt. Note that this IV leaks the SSRC to the receiver but since this is
     * randomly generated and SFUs may not rewrite this is considered acceptable.
     * The SSRC is used to allow demultiplexing multiple streams with the same key, as described in
     *   https://tools.ietf.org/html/rfc3711#section-4.1.1
     * The RTP timestamp is 32 bits and advances by the codec clock rate (90khz for video, 48khz for
     * opus audio) every second. For video it rolls over roughly every 13 hours.
     * The send counter will advance at the frame rate (30fps for video, 50fps for 20ms opus audio)
     * every second. It will take a long time to roll over.
     *
     * See also https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams
     */
    _makeIV(synchronizationSource: number, timestamp: number) {
        const iv = new ArrayBuffer(IV_LENGTH);
        const ivView = new DataView(iv);

        // having to keep our own send count (similar to a picture id) is not ideal.
        if (!this._sendCounts.has(synchronizationSource)) {
            // Initialize with a random offset, similar to the RTP sequence number.
            const randomOffset = crypto.getRandomValues(new Uint16Array(1))[0];
            this._sendCounts.set(synchronizationSource, randomOffset);
        }

        const sendCount = this._sendCounts.get(synchronizationSource) ?? 0;

        ivView.setUint32(0, synchronizationSource);
        ivView.setUint32(4, timestamp);
        ivView.setUint32(8, sendCount % 0xffff);

        this._sendCounts.set(synchronizationSource, sendCount + 1);

        return new Uint8Array(iv);
    }
}
