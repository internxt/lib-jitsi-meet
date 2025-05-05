import { Context } from "./Context";
import { logError, logInfo } from "./crypto-workers";

export function setupWorker(self: {
    postMessage: (data: any) => void;
    onmessage: ((event: MessageEvent) => void) | null;
    onrtctransform?: (event: any) => void;
    RTCTransformEvent?: any;
}) {
    class E2EEWorker {
        private readonly contexts: Map<string, Context>;

        constructor(selfInstance: typeof self) {
            this.contexts = new Map();

            selfInstance.onmessage = this.handleMessage.bind(this);

            if (self.RTCTransformEvent) {
                self.onrtctransform = this.handleRTCTransform.bind(this);
            }
        }

        private getParticipantContext(participantId: string): Context {
            let context = this.contexts.get(participantId);
            if (!context) {
                context = new Context(participantId);
                this.contexts.set(participantId, context);
            }
            return context;
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
                logError(`Invalid operation: ${operation}`);
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
                    logInfo("Stopped encrypting my frames!");
                    break;
                }

                default:
                    logError(`Worker received unknown operation: ${operation}`);
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

    return new E2EEWorker(self);
}

setupWorker(self);
