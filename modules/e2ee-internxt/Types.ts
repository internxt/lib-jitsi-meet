// vodozemac message types
export const PREKEY_MESSAGE = 0;
export const NORMAL_MESSAGE = 1;

export const OLM_MESSAGE = 'olm';
export const OLM_MESSAGE_TYPES = {
    CHAT_KEY: 'chat-key',
    CHAT_KEY_REQUEST: 'chat-key-request',
    ERROR: 'error',
    KEY_INFO: 'key-info',
    KEY_UPDATE: 'key-update',
    KEY_UPDATE_REQ: 'key-update-request',
    PQ_SESSION_ACK: 'pq-session-ack',
    PQ_SESSION_INIT: 'pq-session-init',
    SESSION_ACK: 'session-ack',
    SESSION_DONE: 'session-done',
    SESSION_INIT: 'session-init',
};
export type MessageType =
    (typeof OLM_MESSAGE_TYPES)[keyof typeof OLM_MESSAGE_TYPES];

export const PROTOCOL_STATUS = {
    DONE: 'protocol-established',
    READY_TO_START: 'ready-to-start',
    TERMINATED: 'protocol-terminated',
    WAITING_DONE: 'waiting-for-done',
    WAITING_PQ_SESSION_ACK: 'waiting-for-pq-session-ack',
    WAITING_PQ_SESSION_INIT: 'waiting-for-pq-session-init',
    WAITING_SESSION_ACK: 'waiting-for-session-ack',
};

export type ProtocolStatus =
    (typeof PROTOCOL_STATUS)[keyof typeof PROTOCOL_STATUS];

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

export type MediaKeys = {
    index: number;
    olmKey: Uint8Array;
    pqKey: Uint8Array;
    userID: string;
};

export class CryptoError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'CryptoError';
    }
}
