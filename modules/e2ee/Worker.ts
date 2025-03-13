/* global TransformStream */

// Worker for E2EE/Insertable streams.
import { Context } from "./Context";

const contexts = new Map<string, Context>(); // Map participant id => context

/**
 * Retrieves the participant {@code Context}, creating it if necessary.
 *
 * @param {string} participantId - The participant whose context we need.
 * @returns {Context} The context.
 */
function getParticipantContext(participantId) {
    if (!contexts.has(participantId)) {
        contexts.set(participantId, new Context(participantId));
    }
    return contexts.get(participantId);
}

/**
 * Computes SAS material based on current keys in contexts.
 *
 * @returns {string} The sas material.
 */
function getCurrentSASMaterial(): string {
    let array: string[] = [];
    for (const [pId, context] of contexts) {
        const pHash = context.getHash();
        array.push(pId + pHash);
    }
    array.sort();
    return array.join("");
}

/**
 * Sets an encode / decode transform.
 *
 * @param {Context} context - The participant context where the transform will be applied.
 * @param {string} operation - Encode / decode.
 * @param {ReadableStream} readableStream - Readable stream part.
 * @param {WritableStream} writableStream - Writable stream part.
 */
function handleTransform(
    context: Context,
    operation: string,
    readableStream: ReadableStream,
    writableStream: WritableStream,
) {
    if (operation === "encode" || operation === "decode") {
        const transformFn =
            operation === "encode"
                ? context.encodeFunction
                : context.decodeFunction;
        const transformStream = new TransformStream({
            transform: transformFn.bind(context),
        });

        readableStream.pipeThrough(transformStream).pipeTo(writableStream);
    } else {
        console.error(`E2E: Invalid operation: ${operation}`);
    }
}

onmessage = async (event) => {
    const { operation } = event.data;

    if (operation === "encode" || operation === "decode") {
        const { readableStream, writableStream, participantId } = event.data;
        const context = getParticipantContext(participantId);
        handleTransform(context, operation, readableStream, writableStream);
    } else if (operation === "setKey") {
        const { participantId, olmKey, pqKey, index } = event.data;
        const context = getParticipantContext(participantId);
        await context.setKey(olmKey, pqKey, index);
        const sas = getCurrentSASMaterial();
        self.postMessage({ operation: "updateSAS", sas });
    } else if (operation === "setKeysCommitment") {
        const { participantId, commitment } = event.data;
        const context = getParticipantContext(participantId);
        await context.setKeyCommitment(commitment);
    } else if (operation === "initKeys") {
        const { participantId, commitment, olmKey, pqKey, index } = event.data;
        const context = getParticipantContext(participantId);
        await context.setKeyCommitment(commitment);
        await context.setKey(olmKey, pqKey, index);
    } else if (operation === "ratchetKeys") {
        const { participantId } = event.data;
        const context = getParticipantContext(participantId);
        await context.ratchetKeys();
    } else if (operation === "cleanup") {
        const { participantId } = event.data;
        contexts.delete(participantId);
    } else if (operation === "cleanupAll") {
        contexts.clear();
        console.info("E2E: Stopped encryption of my frames!");
    } else {
        console.error("E2E: e2ee worker", operation);
    }
};

// Operations using RTCRtpScriptTransform.
if (self.RTCTransformEvent) {
    self.onrtctransform = (event) => {
        const transformer = event.transformer;
        const { operation, participantId } = transformer.options;
        const context = getParticipantContext(participantId);
        handleTransform(
            context,
            operation,
            transformer.readable,
            transformer.writable,
        );
    };
}
