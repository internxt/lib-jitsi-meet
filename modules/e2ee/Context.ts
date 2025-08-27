import {
    deriveEncryptionKey,
    ratchetKey,
    hashKeysOfParticipant,
    logError,
    logInfo,
} from "./crypto-workers";
import { KEYRING_SIZE, UNENCRYPTED_BYTES_NUMBER, IV_LENGTH } from "./Constants";
import { symmetric, MediaKeys } from 'internxt-crypto';

let printEncStart = true;

/**
 * Per-participant context holding the cryptographic keys
 */
export class Context {
    private readonly id: string;
    private encryptionKey: CryptoKey;
    private key: MediaKeys;
    private hash: string;
    private commitment: string;

    constructor(id: string) {
        this.encryptionKey = null as any;
        this.key = { olmKey: new Uint8Array(), pqKey: new Uint8Array(), index: -1, userID: id};
        this.id = id;
        this.commitment = "";
        this.hash = "";
    }

    async ratchetKeys() {
        const currentIndex = this.key.index;
        if (currentIndex >= 0) {
            const newMaterialOlm = await ratchetKey(this.key.olmKey);
            const newMaterialPQ = await ratchetKey(this.key.pqKey);
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
     * @param {number} index The keys index.s
     */
    async setKey(olmKey: Uint8Array, pqKey: Uint8Array, index: number) {
        this.key = {olmKey, pqKey, index:  index % KEYRING_SIZE, userID: this.id};
        this.encryptionKey = await deriveEncryptionKey(this.key.olmKey, pqKey);
        this.hash = await hashKeysOfParticipant(
            this.key,
            this.commitment,
        );
        logInfo(
            `Set keys for ${this.id}, index is ${this.key.index} and hash is ${this.hash}`,
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
        if (this.key.index >= 0) {
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
     * 1) Leave the first byte unencrypted
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
        const keyIndex = this.key.index;
        try {
            // Thіs is not encrypted and contains the VP8 payload descriptor or the Opus TOC byte.
            const frameHeader = new Uint8Array(
                encodedFrame.data,
                0,
                UNENCRYPTED_BYTES_NUMBER,
            );

            // Construct frame trailer. Similar to the frame header described in
            // https://tools.ietf.org/html/draft-omara-sframe-00#section-4.2
            // but we put it at the end.
            //
            // ---------+-------------------------+-+---------+----
            // payload  |IV...(length = IV_LENGTH)|R|IV_LENGTH|KID |
            // ---------+-------------------------+-+---------+----
            const data: Uint8Array = new Uint8Array(
                encodedFrame.data,
                UNENCRYPTED_BYTES_NUMBER,
            );
            const additionalData = new Uint8Array(
                encodedFrame.data,
                0,
                UNENCRYPTED_BYTES_NUMBER,
            );
            const {iv, ciphertext: cipherText} = await symmetric.encryptSymmetrically(key, data, additionalData.toString());

            const newData = new ArrayBuffer(
                UNENCRYPTED_BYTES_NUMBER +
                    cipherText.byteLength +
                    IV_LENGTH +
                    1,
            );
            const newUint8 = new Uint8Array(newData);

            newUint8.set(frameHeader); // copy first bytes.
            newUint8.set(new Uint8Array(cipherText), UNENCRYPTED_BYTES_NUMBER); // add ciphertext.
            newUint8.set(
                new Uint8Array(iv),
                UNENCRYPTED_BYTES_NUMBER + cipherText.byteLength,
            ); // append IV.
            newUint8.set(
                new Uint8Array([keyIndex]),
                UNENCRYPTED_BYTES_NUMBER + cipherText.byteLength + IV_LENGTH,
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
        if (keyIndex === this.key.index) {
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
            const iv = new Uint8Array(
                encodedFrame.data,
                encodedFrame.data.byteLength - IV_LENGTH - 1,
                IV_LENGTH,
            );

            const cipherTextLength =
                encodedFrame.data.byteLength -
                (UNENCRYPTED_BYTES_NUMBER + IV_LENGTH + 1);

            const additionalData = new Uint8Array(
                encodedFrame.data,
                0,
                UNENCRYPTED_BYTES_NUMBER,
            );
            const data = new Uint8Array(
                encodedFrame.data,
                UNENCRYPTED_BYTES_NUMBER,
                cipherTextLength,
            );
            const plainText = await  symmetric.decryptSymmetrically(encryptionKey, {iv, ciphertext: data}, additionalData.toString());

            const newData = new ArrayBuffer(
                UNENCRYPTED_BYTES_NUMBER + plainText.byteLength,
            );
            const newUint8 = new Uint8Array(newData);

            newUint8.set(
                new Uint8Array(encodedFrame.data, 0, UNENCRYPTED_BYTES_NUMBER),
            );
            newUint8.set(new Uint8Array(plainText), UNENCRYPTED_BYTES_NUMBER);

            encodedFrame.data = newData;

            return encodedFrame;
        } catch (error) {
            logError(`Decryption of a frame from ${this.id} failed: ${error}`);
        }
    }
}
