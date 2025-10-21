/* eslint-disable no-bitwise */
import { Context } from "../modules/e2ee-internxt/Context";
import { deriveKey } from "internxt-crypto";

const audioBytes = [0xde, 0xad, 0xbe, 0xef];
const videoBytes = [
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
];

/**
 * generates a dummy audio frame
 */
function makeAudioFrame(): RTCEncodedAudioFrame {
    return {
        data: new Uint8Array(audioBytes).buffer,
        timestamp: performance.now() * 1000,
        getMetadata: () => {
            return { synchronizationSource: 123 };
        },
    };
}

/**
 * generates a dummy video frame
 */
function makeVideoFrame(): RTCEncodedVideoFrame {
    return {
        data: new Uint8Array(videoBytes).buffer,
        timestamp: performance.now() * 1000,
        type: "key",
        getMetadata: () => {
            return { synchronizationSource: 321 };
        },
    };
}

describe("E2EE Context", () => {
    let sender: Context;
    let sendController: TransformStreamDefaultController;
    let receiver: Context;
    let receiveController: TransformStreamDefaultController;
    const olmKey = new Uint8Array([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    ]);

    const pqKey = new Uint8Array([
        2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    const key = { olmKey, pqKey, index: 0, userID: "id" };

    beforeEach(() => {
        sender = new Context("sender");
        receiver = new Context("receiver");
    });

    describe("encode function", () => {
        beforeEach(async () => {
            await sender.setKey(key);
            await receiver.setKey(key);
        });

        it("with an audio frame", (done) => {
            sendController = {
                enqueue: (encodedFrame:  RTCEncodedVideoFrame | RTCEncodedAudioFrame) => {
                    const data = new Uint8Array(encodedFrame.data);

                    // An audio frame will have an overhead of 33 bytes and key size:
                    // 16 bytes authentication tag, 16 bytes iv and 1 byte key index.
                    expect(data.byteLength).toEqual(audioBytes.length + 33);
                    expect(data[0]).toEqual(222);
                    done();
                },
                error(reason) {
                    this.error = reason || new Error("Unknown error");
                },
                terminate() {
                },
                desiredSize: 222,
            };

            sender.encodeFunction(makeAudioFrame(), sendController);
        });

        it("with a video frame", (done) => {
            sendController = {
                enqueue: (encodedFrame:  RTCEncodedVideoFrame | RTCEncodedAudioFrame) => {
                    const data = new Uint8Array(encodedFrame.data);

                    // A video frame will have an overhead of 34 bytes and key size:
                    // 16 bytes authentication tag, 16 bytes iv and 1 byte key index.
                    expect(data.byteLength).toEqual(videoBytes.length + 33);
                    expect(data[0]).toEqual(222);
                    done();
                },
                 error(reason) {
                    this.error = reason || new Error("Unknown error");
                },
                terminate() {
                },
                desiredSize: 222,
            };

            sender.encodeFunction(makeVideoFrame(), sendController);
        });
    });

    describe("end-to-end test", () => {
        beforeEach(async () => {
            await sender.setKey(key);
            await receiver.setKey(key);
            sendController = {
                enqueue: async (encodedFrame:  RTCEncodedVideoFrame | RTCEncodedAudioFrame) => {
                    await receiver.decodeFunction(
                        encodedFrame,
                        receiveController,
                    );
                },
                 error(reason) {
                    this.error = reason || new Error("Unknown error");
                },
                terminate() {
                },
                desiredSize: 222,
            };
        });

        it("with an audio frame", (done) => {
            receiveController = {
                enqueue: (encodedFrame) => {
                    const data = new Uint8Array(encodedFrame.data);

                    expect(data.byteLength).toEqual(audioBytes.length);
                    expect(Array.from(data)).toEqual(audioBytes);
                    done();
                },
                 error(reason) {
                    this.error = reason || new Error("Unknown error");
                },
                terminate() {
                },
                desiredSize: 222,
            };
            sender.encodeFunction(makeAudioFrame(), sendController);
        });

        it("with a video frame", (done) => {
            receiveController = {
                enqueue: (encodedFrame:  RTCEncodedVideoFrame | RTCEncodedAudioFrame) => {
                    const data = new Uint8Array(encodedFrame.data);

                    expect(data.byteLength).toEqual(videoBytes.length);
                    expect(Array.from(data)).toEqual(videoBytes);
                    done();
                },
                 error(reason) {
                    this.error = reason || new Error("Unknown error");
                },
                terminate() {
                },
                desiredSize: 222,
            };

            sender.encodeFunction(makeVideoFrame(), sendController);
        });

        it("the receiver ratchets forward", (done) => {
            receiveController = {
                enqueue: (encodedFrame:  RTCEncodedVideoFrame | RTCEncodedAudioFrame) => {
                    const data = new Uint8Array(encodedFrame.data);

                    expect(data.byteLength).toEqual(audioBytes.length);
                    expect(Array.from(data)).toEqual(audioBytes);
                    done();
                },
                 error(reason) {
                    this.error = reason || new Error("Unknown error");
                },
                terminate() {
                },
                desiredSize: 222,
            };

            const encodeFunction = async () => {
                // Ratchet the key for both
                const newKey = await deriveKey.ratchetMediaKey({
                    olmKey: olmKey,
                    pqKey,
                    index: 0,
                    userID: "id",
                });

                await sender.setKey(newKey);
                await receiver.setKey(newKey);
                sender.encodeFunction(makeAudioFrame(), sendController);
            };

            encodeFunction();
        });
    });
});
