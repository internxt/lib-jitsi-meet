/* tslint:disable */
/* eslint-disable */
export function verify_signature(key: string, message: Uint8Array, signature: string): void;
export function main(): void;
export class Account {
  free(): void;
  constructor();
  static from_pickle(pickle: string, pickle_key: Uint8Array): Account;
  static from_libolm_pickle(pickle: string, pickle_key: Uint8Array): Account;
  pickle(pickle_key: Uint8Array): string;
  sign(message: string): string;
  generate_one_time_keys(count: number): void;
  forget_fallback_key(): boolean;
  generate_fallback_key(): void;
  mark_keys_as_published(): void;
  create_outbound_session(identity_key: string, one_time_key: string): Session;
  create_inbound_session(identity_key: string, message_type: number, ciphertext: string): InboundCreationResult;
  readonly ed25519_key: string;
  readonly curve25519_key: string;
  readonly max_number_of_one_time_keys: number;
  readonly one_time_keys: any;
  readonly fallback_key: any;
}
export class DecryptedMessage {
  private constructor();
  free(): void;
  plaintext: Uint8Array;
  message_index: number;
}
export class EncryptedOlmMessage {
  private constructor();
  free(): void;
  ciphertext: string;
  message_type: number;
}
export class EstablishedSas {
  private constructor();
  free(): void;
  bytes(info: string): SasBytes;
  calculate_mac(input: string, info: string): string;
  calculate_mac_invalid_base64(input: string, info: string): string;
  verify_mac(input: string, info: string, tag: string): void;
}
export class GroupSession {
  free(): void;
  constructor();
  encrypt(plaintext: Uint8Array): string;
  pickle(pickle_key: Uint8Array): string;
  static from_pickle(pickle: string, pickle_key: Uint8Array): GroupSession;
  readonly session_id: string;
  readonly session_key: string;
  readonly message_index: number;
}
export class InboundCreationResult {
  private constructor();
  free(): void;
  readonly session: Session;
  readonly plaintext: Uint8Array;
}
export class InboundGroupSession {
  free(): void;
  constructor(session_key: string);
  static import(session_key: string): InboundGroupSession;
  export_at(index: number): string | undefined;
  decrypt(ciphertext: string): DecryptedMessage;
  pickle(pickle_key: Uint8Array): string;
  static from_pickle(pickle: string, pickle_key: Uint8Array): InboundGroupSession;
  static from_libolm_pickle(pickle: string, pickle_key: Uint8Array): InboundGroupSession;
  readonly session_id: string;
  readonly first_known_index: number;
}
export class Sas {
  free(): void;
  constructor();
  diffie_hellman(key: string): EstablishedSas;
  readonly public_key: string;
}
export class SasBytes {
  private constructor();
  free(): void;
  readonly emoji_indices: Uint8Array;
  readonly decimals: Uint16Array;
}
export class Session {
  private constructor();
  free(): void;
  pickle(pickle_key: Uint8Array): string;
  static from_pickle(pickle: string, pickle_key: Uint8Array): Session;
  static from_libolm_pickle(pickle: string, pickle_key: Uint8Array): Session;
  session_matches(message_type: number, ciphertext: string): boolean;
  encrypt(plaintext: Uint8Array): EncryptedOlmMessage;
  decrypt(message_type: number, ciphertext: string): Uint8Array;
  has_received_message(): boolean;
  readonly session_id: string;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_groupsession_free: (a: number, b: number) => void;
  readonly groupsession_new: () => number;
  readonly groupsession_session_id: (a: number) => [number, number];
  readonly groupsession_session_key: (a: number) => [number, number];
  readonly groupsession_message_index: (a: number) => number;
  readonly groupsession_encrypt: (a: number, b: number, c: number) => [number, number];
  readonly groupsession_pickle: (a: number, b: number, c: number) => [number, number, number, number];
  readonly groupsession_from_pickle: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly __wbg_decryptedmessage_free: (a: number, b: number) => void;
  readonly __wbg_get_decryptedmessage_plaintext: (a: number) => [number, number];
  readonly __wbg_set_decryptedmessage_plaintext: (a: number, b: number, c: number) => void;
  readonly __wbg_get_decryptedmessage_message_index: (a: number) => number;
  readonly __wbg_set_decryptedmessage_message_index: (a: number, b: number) => void;
  readonly __wbg_inboundgroupsession_free: (a: number, b: number) => void;
  readonly inboundgroupsession_new: (a: number, b: number) => [number, number, number];
  readonly inboundgroupsession_import: (a: number, b: number) => [number, number, number];
  readonly inboundgroupsession_session_id: (a: number) => [number, number];
  readonly inboundgroupsession_first_known_index: (a: number) => number;
  readonly inboundgroupsession_export_at: (a: number, b: number) => [number, number];
  readonly inboundgroupsession_decrypt: (a: number, b: number, c: number) => [number, number, number];
  readonly inboundgroupsession_pickle: (a: number, b: number, c: number) => [number, number, number, number];
  readonly inboundgroupsession_from_pickle: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly inboundgroupsession_from_libolm_pickle: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly __wbg_account_free: (a: number, b: number) => void;
  readonly __wbg_inboundcreationresult_free: (a: number, b: number) => void;
  readonly inboundcreationresult_session: (a: number) => number;
  readonly inboundcreationresult_plaintext: (a: number) => [number, number];
  readonly account_new: () => number;
  readonly account_from_pickle: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly account_from_libolm_pickle: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly account_pickle: (a: number, b: number, c: number) => [number, number, number, number];
  readonly account_ed25519_key: (a: number) => [number, number];
  readonly account_curve25519_key: (a: number) => [number, number];
  readonly account_sign: (a: number, b: number, c: number) => [number, number];
  readonly account_max_number_of_one_time_keys: (a: number) => number;
  readonly account_one_time_keys: (a: number) => [number, number, number];
  readonly account_generate_one_time_keys: (a: number, b: number) => void;
  readonly account_fallback_key: (a: number) => [number, number, number];
  readonly account_forget_fallback_key: (a: number) => number;
  readonly account_generate_fallback_key: (a: number) => void;
  readonly account_mark_keys_as_published: (a: number) => void;
  readonly account_create_outbound_session: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
  readonly account_create_inbound_session: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
  readonly __wbg_encryptedolmmessage_free: (a: number, b: number) => void;
  readonly __wbg_get_encryptedolmmessage_ciphertext: (a: number) => [number, number];
  readonly __wbg_set_encryptedolmmessage_ciphertext: (a: number, b: number, c: number) => void;
  readonly __wbg_get_encryptedolmmessage_message_type: (a: number) => number;
  readonly __wbg_set_encryptedolmmessage_message_type: (a: number, b: number) => void;
  readonly __wbg_session_free: (a: number, b: number) => void;
  readonly session_pickle: (a: number, b: number, c: number) => [number, number, number, number];
  readonly session_from_pickle: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly session_from_libolm_pickle: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly session_session_id: (a: number) => [number, number];
  readonly session_session_matches: (a: number, b: number, c: number, d: number) => number;
  readonly session_encrypt: (a: number, b: number, c: number) => number;
  readonly session_decrypt: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly session_has_received_message: (a: number) => number;
  readonly __wbg_sas_free: (a: number, b: number) => void;
  readonly sas_new: () => number;
  readonly sas_public_key: (a: number) => [number, number];
  readonly sas_diffie_hellman: (a: number, b: number, c: number) => [number, number, number];
  readonly __wbg_establishedsas_free: (a: number, b: number) => void;
  readonly establishedsas_bytes: (a: number, b: number, c: number) => number;
  readonly establishedsas_calculate_mac: (a: number, b: number, c: number, d: number, e: number) => [number, number];
  readonly establishedsas_calculate_mac_invalid_base64: (a: number, b: number, c: number, d: number, e: number) => [number, number];
  readonly establishedsas_verify_mac: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number];
  readonly __wbg_sasbytes_free: (a: number, b: number) => void;
  readonly sasbytes_emoji_indices: (a: number) => [number, number];
  readonly sasbytes_decimals: (a: number) => [number, number];
  readonly verify_signature: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
  readonly main: () => void;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_2: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
