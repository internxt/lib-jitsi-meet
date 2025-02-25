export class Context {
    constructor(id: string);
    setKey: (
        olmKey: Uint8Array,
        pqKey: Uint8Array,
        index: number,
    ) => Promise<void>;
    ratchetKeys: () => Promise<void>;
    setDecryptionFlag: (decryptionFlag: boolean) => void;
    encodeFunction: (
        encodedFrame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
        controller: TransformStreamDefaultController,
    ) => void;
    decodeFunction: (
        encodedFrame: RTCEncodedVideoFrame | RTCEncodedAudioFrame,
        controller: TransformStreamDefaultController,
    ) => Promise<void>;
}
