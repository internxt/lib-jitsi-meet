import {
    symmetric,
    MediaKeys,
    deriveKey,
    hash,
    utils,
    IV_LEN_BYTES,
} from "internxt-crypto";

// We copy the first bytes of the VP8 payload unencrypted.
// This allows the bridge to continue detecting keyframes (only one byte needed in the JVB)
//    https://tools.ietf.org/html/rfc6386#section-9.1
//
// For audio (where frame.type is not set) we do not encrypt the opus TOC byte:
//   https://tools.ietf.org/html/rfc6716#section-3.1
const UNENCRYPTED_BYTES_NUMBER = 1;

export const MAX_NUMBER_TO_FIT_BYTE = 255;

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
        this.key = {
            olmKey: new Uint8Array(),
            pqKey: new Uint8Array(),
            index: -1,
            userID: id,
        };
        this.id = id;
        this.commitment = "";
        this.hash = "";
    }

    async ratchetKeys() {
        if (this.key.index >= 0) {
            const key = await deriveKey.ratchetMediaKey(this.key);
            this.setKey(key);
        }
    }

    setKeyCommitment(commitment: string) {
        this.commitment = commitment;
    }

    getHash() {
        return this.hash;
    }

    /**
     * Derives the encryption key and sets participant key.
     * @param {MediaKeys} key The new key.
     */
    async setKey(key: MediaKeys) {
        this.key = key;
        this.encryptionKey =
            await deriveKey.deriveSymmetricCryptoKeyFromTwoKeys(
                this.key.olmKey,
                this.key.pqKey,
            );
        const keyBase64 = utils.mediaKeysToBase64(this.key);
        this.hash = await hash.hashData([keyBase64, this.commitment]);
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
     * 2) Encrypt the rest of the frame using AES-GCM.
     * 3) Allocate space for the encrypted frame.
     * 4) Copy the unencrypted bytes to the start of the encrypted frame.
     * 5) Append the ciphertext to the encrypted frame.
     * 6) Append the IV.
     * 7) Append a single byte for the key identifier.
     * 8) Enqueue the encrypted frame for sending.
     */
    async _encryptFrame(
        encodedFrame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
    ) {
        const key: CryptoKey = this.encryptionKey;
        const keyIndex = new Uint8Array([
            this.key.index % MAX_NUMBER_TO_FIT_BYTE,
        ]);
        try {
            // Thіs is not encrypted and contains the VP8 payload descriptor or the Opus TOC byte.
            const unencryptedPart = new Uint8Array(
                encodedFrame.data,
                0,
                UNENCRYPTED_BYTES_NUMBER,
            );

            // Construct frame trailer. Similar to the frame header described in
            // https://tools.ietf.org/html/draft-omara-sframe-00#section-4.2
            // but we put it at the end.
            //
            // +------------------+-----------------+----+-----------+
            // | unencrypted byte | encrypted data  | IV | key index |
            // +------------------+-----------------+----+-----------+
            const data: Uint8Array = new Uint8Array(
                encodedFrame.data,
                UNENCRYPTED_BYTES_NUMBER,
            );
            const additionalData = new Uint8Array(
                encodedFrame.data,
                0,
                UNENCRYPTED_BYTES_NUMBER,
            );
            const freeField = [
                encodedFrame.getMetadata().synchronizationSource,
                encodedFrame.timestamp,
            ].toString();
            const { iv, ciphertext } = await symmetric.encryptSymmetrically(
                key,
                data,
                additionalData.toString(),
                freeField,
            );

            const newUint8 = new Uint8Array(
                UNENCRYPTED_BYTES_NUMBER +
                    ciphertext.byteLength +
                    IV_LEN_BYTES +
                    1,
            );

            newUint8.set(unencryptedPart); // copy undencrypted byte.
            newUint8.set(ciphertext, UNENCRYPTED_BYTES_NUMBER); // add ciphertext.
            newUint8.set(iv, UNENCRYPTED_BYTES_NUMBER + ciphertext.byteLength); // append IV.
            newUint8.set(
                keyIndex,
                UNENCRYPTED_BYTES_NUMBER + ciphertext.byteLength + IV_LEN_BYTES,
            ); // append key index.

            encodedFrame.data = newUint8.buffer;
            return encodedFrame;
        } catch (e) {
            console.error(`Encryption failed: ${e}`);
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
                encodedFrame.data.byteLength - IV_LEN_BYTES - 1,
                IV_LEN_BYTES,
            );

            const cipherTextLength =
                encodedFrame.data.byteLength -
                (UNENCRYPTED_BYTES_NUMBER + IV_LEN_BYTES + 1);

            const additionalData = new Uint8Array(
                encodedFrame.data,
                0,
                UNENCRYPTED_BYTES_NUMBER,
            );
            const ciphertext = new Uint8Array(
                encodedFrame.data,
                UNENCRYPTED_BYTES_NUMBER,
                cipherTextLength,
            );
            const plainText = await symmetric.decryptSymmetrically(
                encryptionKey,
                { iv, ciphertext },
                additionalData.toString(),
            );

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
            console.error(
                `Decryption of a frame from ${this.id} failed: ${error}`,
            );
        }
    }
}
