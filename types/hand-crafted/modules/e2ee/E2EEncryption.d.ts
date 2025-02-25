import JitsiConference from "../../JitsiConference";
import JitsiParticipant from "../../JitsiParticipant";

declare class E2EEncryption {
    constructor(conference: JitsiConference);
    static isSupported: (config: {
        testing: { disableE2EE: boolean };
    }) => boolean;
    isEnabled: () => boolean;
    setEnabled: (enabled: boolean) => Promise<void>;
    setEncryptionKey: (
        olmKey: Uint8Array,
        pqKey: Uint8Array,
        index: number,
    ) => void;
    startVerification: (participant: JitsiParticipant) => void;
    markParticipantVerified: (
        participant: JitsiParticipant,
        isVerified: boolean,
    ) => void;
}
