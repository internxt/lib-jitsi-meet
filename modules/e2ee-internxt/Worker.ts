import { Context } from "./Context";

type WorkerLike = {
    postMessage: (data: any) => void;
    onmessage: ((event: MessageEvent) => void) | null;
    onrtctransform?: (event: any) => void;
    RTCTransformEvent?: any;
};

class E2EEWorker {
    private readonly contexts: Map<string, Context>;
    private readonly _self: WorkerLike;

    constructor(selfInstance: WorkerLike) {
        this.contexts = new Map();
        this._self = selfInstance;

        selfInstance.onmessage = this.handleMessage.bind(this);

        if (this._self.RTCTransformEvent) {
            this._self.onrtctransform = this.handleRTCTransform.bind(this);
        }
    }

    private createParticipantContext(
        participantId: string,
    ): Context | undefined {
        if (this.contexts.has(participantId)) {
            return undefined;
        }

        const context = new Context(participantId);
        this.contexts.set(participantId, context);
        return context;
    }

    private getParticipantContext(participantId: string): Context | undefined {
        return this.contexts.get(participantId);
    }

    private getCurrentSASMaterial(): string {
        return [...this.contexts.entries()]
            .map(([pId, context]) => pId + (context.getHash() || ""))
            .sort((a, b) => a.localeCompare(b))
            .join("");
    }

    private handleTransform(
        context: Context,
        operation: string,
        readableStream: ReadableStream,
        writableStream: WritableStream,
    ): void {
        if (operation !== "encode" && operation !== "decode") {
            console.error(`Invalid operation: ${operation}`);
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
                const { readableStream, writableStream, participantId } =
                    event.data;
                const context = this.getParticipantContext(participantId);
                if (!context) break;
                this.handleTransform(
                    context,
                    operation,
                    readableStream,
                    writableStream,
                );
                break;
            }

            case "setKey": {
                const { participantId, olmKey, pqKey, index } = event.data;
                const context = this.getParticipantContext(participantId);
                if (!context) break;
                await context.setKey({
                    olmKey,
                    pqKey,
                    index,
                    userID: participantId,
                });
                const sas = this.getCurrentSASMaterial();
                this._self.postMessage({ operation: "updateSAS", sas });
                break;
            }

            case "setKeysCommitment": {
                const { participantId, pk, pkKyber } = event.data;
                const context = this.createParticipantContext(participantId);
                if (!context) break;
                await context.setKeyCommitment(pk, pkKyber);
                break;
            }

            case "ratchetKeys": {
                const { participantId } = event.data;
                const context = this.getParticipantContext(participantId);
                if (!context) break;
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
                console.info("Stopped encrypting my frames!");
                break;
            }

            default:
                console.error(
                    `Worker received unknown operation: ${operation}`,
                );
        }
    }

    private handleRTCTransform(event: any): void {
        const transformer = event.transformer;
        const { operation, participantId } = transformer.options;
        const context = this.getParticipantContext(participantId);
        if (!context) {
            return;
        }
        this.handleTransform(
            context,
            operation,
            transformer.readable,
            transformer.writable,
        );
    }
}

export function setupWorker(self: WorkerLike): E2EEWorker {
    return new E2EEWorker(self);
}

setupWorker(self);
