import { Context } from "./Context";

export class E2EEWorker {
    private readonly contexts: Map<string, Context>;

    constructor() {
        this.contexts = new Map();

        self.onmessage = this.handleMessage.bind(this);

        if ((self as any).RTCTransformEvent) {
            (self as any).onrtctransform = this.handleRTCTransform.bind(this);
        }
    }

    private getParticipantContext(participantId: string): Context {
        if (!this.contexts.has(participantId)) {
            this.contexts.set(participantId, new Context(participantId));
        }
        return this.contexts.get(participantId);
    }

    private getCurrentSASMaterial(): string {
        const array: string[] = [];
        for (const [pId, context] of this.contexts) {
            const pHash = context.getHash();
            if (pHash) array.push(pId + pHash);
        }
        array.sort((a, b) => a.localeCompare(b));
        return array.join("");
    }

    private handleTransform(
        context: Context,
        operation: string,
        readableStream: ReadableStream,
        writableStream: WritableStream,
    ): void {
        if (operation !== "encode" && operation !== "decode") {
            console.error(`E2E: Invalid operation: ${operation}`);
            return;
        }

        const transformFn =
            operation === "encode"
                ? context.encodeFunction
                : context.decodeFunction;

        const transformStream = new TransformStream({
            transform: transformFn.bind(context),
        });

        readableStream.pipeThrough(transformStream).pipeTo(writableStream);
    }

    private async handleMessage(event: MessageEvent): Promise<void> {
        const { operation } = event.data;

        switch (operation) {
            case "encode":
            case "decode": {
                const { readableStream, writableStream, participantId } = event.data;
                const context = this.getParticipantContext(participantId);
                this.handleTransform(context, operation, readableStream, writableStream);
                break;
            }

            case "setKey": {
                const { participantId, olmKey, pqKey, index } = event.data;
                const context = this.getParticipantContext(participantId);
                await context.setKey(olmKey, pqKey, index);
                const sas = this.getCurrentSASMaterial();
                self.postMessage({ operation: "updateSAS", sas });
                break;
            }

            case "setKeysCommitment": {
                const { participantId, commitment } = event.data;
                const context = this.getParticipantContext(participantId);
                await context.setKeyCommitment(commitment);
                break;
            }

            case "ratchetKeys": {
                const { participantId } = event.data;
                const context = this.getParticipantContext(participantId);
                await context.ratchetKeys();
                break;
            }

            case "cleanup": {
                const { participantId } = event.data;
                this.contexts.delete(participantId);
                break;
            }

            case "cleanupAll": {
                this.contexts.clear();
                console.info("E2E: Stopped encryption of my frames!");
                break;
            }

            default:
                console.error("E2E: e2ee worker received unknown operation", operation);
                break;
        }
    }

    private handleRTCTransform(event: any): void {
        const transformer = event.transformer;
        const { operation, participantId } = transformer.options;
        const context = this.getParticipantContext(participantId);
        this.handleTransform(
            context,
            operation,
            transformer.readable,
            transformer.writable,
        );
    }
}

// Instantiating the worker class to hook into self.onmessage, etc.
new E2EEWorker();
