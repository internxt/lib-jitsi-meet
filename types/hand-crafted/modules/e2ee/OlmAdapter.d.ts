import JitsiConference from "../../JitsiConference";
import JitsiParticipant from "../../JitsiParticipant";
import Listenable from "../util/Listenable";

export class OlmAdapter extends Listenable {
    constructor(conference: JitsiConference);
    initSessions: () => Promise<void>;
    static isSupported: () => boolean;
    getCurrentKeys: () => {
        olmKey: Uint8Array;
        pqKey: Uint8Array;
        index: number;
    };
    sendKeyInfoToParticipant: (participant: JitsiParticipant) => Promise<void>;
    sendKeyInfoToAll: () => Promise<void>;
    ratchetParticipantKeys: (participant: JitsiParticipant) => Promise<void>;
    ratchetAllKeys: () => Promise<void>;
    markParticipantVerified: (
        participant: JitsiParticipant,
        isVerified: boolean,
    ) => void;
    startVerification: (participant: JitsiParticipant) => void;
    clearParticipantSession: (participant: JitsiParticipant) => void;
    clearAllParticipantsSessions: () => void;
}
