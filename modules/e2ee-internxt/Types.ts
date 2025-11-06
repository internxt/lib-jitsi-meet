// vodozemac message types
export const PREKEY_MESSAGE = 0;
export const NORMAL_MESSAGE = 1;

export const OLM_MESSAGE = 'olm';
export const OLM_MESSAGE_TYPES = {
    ERROR: 'error',
    KEY_INFO: 'key-info',
    KEY_UPDATE: 'key-update',
    KEY_UPDATE_REQ: 'key-update-request',
    SESSION_ACK: 'session-ack',
    PQ_SESSION_ACK: 'pq-session-ack',
    SESSION_INIT: 'session-init',
    PQ_SESSION_INIT: 'pq-session-init',
    SESSION_DONE: 'session-done',
};
export type MessageType =
    (typeof OLM_MESSAGE_TYPES)[keyof typeof OLM_MESSAGE_TYPES];

export const PROTOCOL_STATUS = {
    TERMINATED: 'protocol-terminated',
    READY_TO_START: 'ready-to-start',
    WAITING_SESSION_ACK: 'waiting-for-session-ack',
    WAITING_PQ_SESSION_ACK: 'waiting-for-pq-session-ack',
    WAITING_PQ_SESSION_INIT: 'waiting-for-pq-session-init',
    WAITING_DONE: 'waiting-for-done',
    DONE: 'protocol-established',
};

export type ProtocolStatus =
    (typeof PROTOCOL_STATUS)[keyof typeof PROTOCOL_STATUS];

// Extend the RTCRtpReceiver interface due to lack of support of streams
export interface CustomRTCRtpReceiver extends RTCRtpReceiver {
    createEncodedStreams?: () => {
        readable: ReadableStream;
        writable: WritableStream;
    };
    kJitsiE2EE: boolean;
    transform: RTCRtpScriptTransform;
}

export interface CustomRTCRtpSender extends RTCRtpSender {
    createEncodedStreams?: () => {
        readable: ReadableStream;
        writable: WritableStream;
    };
    kJitsiE2EE: boolean;
    transform: RTCRtpScriptTransform;
}

export type ReplyMessage = KeyInfo | SessionInit | PQsessionInit | PQsessionAck;

export type KeyInfo = {
    ciphertext: string;
    pqCiphertext: string;
};

export type SessionInit = {
    commitment: string;
    otKey: string;
    publicKey: string;
    publicKyberKey: string;
};
export type PQsessionAck = {
    ciphertext: string;
    encapsKyber: string;
    pqCiphertext: string;
};

export type PQsessionInit = {
    ciphertext: string;
    encapsKyber: string;
    publicKey: string;
    publicKyberKey: string;
};

export type ParticipantEvent = {
    id: string;
    type: 'join' | 'leave';
};
