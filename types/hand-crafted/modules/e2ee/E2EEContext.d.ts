export default class E2EEcontext {
    constructor();
    cleanup: (participantId: string) => void;
    cleanupAll: () => void;
    handleReceiver: (receiver: RTCRtpReceiver, participantId: string) => void;
    handleSender: (sender: RTCRtpSender, participantId: string) => void;
    setKey: (
        participantId: string,
        olmKey: Uint8Array,
        pqKey: Uint8Array,
        index: number,
    ) => void;
    ratchetKeys: (participantId: string) => void;
    setDecryptionFlag: (participantId: string, decryptionFlag: boolean) => void;
}
