//vodozemac message types
export const PREKEY_MESSAGE = 0;
export const NORMAL_MESSAGE = 1;

export const OLM_MESSAGE_TYPE = "olm";
export const OLM_MESSAGE_TYPES = {
    ERROR: "error",
    KEY_INFO: "key-info",
    KEY_UPDATED: "key-updated",
    SESSION_ACK: "session-ack",
    PQ_SESSION_ACK: "pq-session-ack",
    SESSION_INIT: "session-init",
    PQ_SESSION_INIT: "pq-session-init",
    SESSION_DONE: "session-done",
};
export type MessageType =
    (typeof OLM_MESSAGE_TYPES)[keyof typeof OLM_MESSAGE_TYPES];

export const PROTOCOL_STATUS = {
    TERMINATED: "protocol-terminated",
    READY_TO_START: "ready-to-start",
    WAITING_SESSION_ACK: "waiting-for-session-ack",
    WAITING_PQ_SESSION_ACK: "waiting-for-pq-session-ack",
    WAITING_PQ_SESSION_INIT: "waiting-for-pq-session-init",
    WAITING_DONE: "waiting-for-done",
    DONE: "protocol-established",
};

export type ProtocolStatus =
    (typeof PROTOCOL_STATUS)[keyof typeof PROTOCOL_STATUS];

// Extend the RTCRtpReceiver interface due to lack of support of streams
export interface CustomRTCRtpReceiver extends RTCRtpReceiver {
    kJitsiE2EE: boolean;
    createEncodedStreams?: () => {
        readable: ReadableStream;
        writable: WritableStream;
    };
    transform: RTCRtpScriptTransform;
}

export interface CustomRTCRtpSender extends RTCRtpSender {
    kJitsiE2EE: boolean;
    createEncodedStreams?: () => {
        readable: ReadableStream;
        writable: WritableStream;
    };
    transform: RTCRtpScriptTransform;
}

export type ReplyMessage =
    | KeyInfo
    | SessionInit
    | PQsessionInit
    | PQsessionAck;

export type KeyInfo = {
    ciphertext: string;
    pqCiphertext: string;
};

export type SessionInit = {
    otKey: string;
    publicKey: string;
    publicKyberKey: string;
    commitment: string;
};
export type PQsessionAck = {
    encapsKyber: string;
    ciphertext: string;
    pqCiphertext: string;
};

export type PQsessionInit = {
    encapsKyber: string;
    publicKey: string;
    publicKyberKey: string;
    ciphertext: string;
};

