/* global TransformStream */

// Worker for E2EE/Insertable streams.
import { Context } from "./Context";
import { deriveSASBytes } from "./crypto-workers";

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
 * Computes SAS bytes based on current keys in contexts.
 *
 * @returns {Uint8Array} The sas bytes.
 */
async function getCurrentSASBytes() {
    let array = [];
    for (const [pId, context] of contexts) {
        const pHash = context.getHash();
        console.log(`E2E: SAS got hash from ${pId}: ${pHash}`);
        array.push(pId + pHash);
    }
    array.sort();
    const str = array.join("");
    return deriveSASBytes(str);
}

/**
 * Sets an encode / decode transform.
 *
 * @param {Object} context - The participant context where the transform will be applied.
 * @param {string} operation - Encode / decode.
 * @param {Object} readableStream - Readable stream part.
 * @param {Object} writableStream - Writable stream part.
 */
function handleTransform(context, operation, readableStream, writableStream) {
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
        const sas = await getCurrentSASBytes();
        self.postMessage({ operation: "updateSAS", sas });
    } else if (operation === "setKeyCommitment") {
        const { participantId, commitment } = event.data;
        const context = getParticipantContext(participantId);
        await context.setKeyCommitment(commitment);
    } else if (operation === "ratchetKeys") {
        const { participantId } = event.data;
        const context = getParticipantContext(participantId);
        await context.ratchetKeys();
    } else if (operation === "setDecryptionFlag") {
        const { participantId, decryptionFlag } = event.data;
        const context = getParticipantContext(participantId);
        context.setDecryptionFlag(decryptionFlag);
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
