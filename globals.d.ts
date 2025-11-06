export {};

declare global {
    type Timeout = ReturnType<typeof setTimeout>;
    interface Window {
        JitsiMeetJS?: {
            app?: {
                connectionTimes?: Record<string, any>;
            };
        };
        connectionTimes?: Record<string, any>;
    }
    interface RTCRtpReceiver {
        createEncodedStreams?: () => {
            readable: ReadableStream<RTCEncodedAudioFrame | RTCEncodedVideoFrame>;
            writable: WritableStream<RTCEncodedAudioFrame | RTCEncodedVideoFrame>;
        };
        kJitsiE2EE?: boolean;
        transform: RTCRtpScriptTransform| null;
    }
    interface RTCRtpSender {
        createEncodedStreams?: () => {
            readable: ReadableStream;
            writable: WritableStream;
        };
        kJitsiE2EE?: boolean;
        transform: RTCRtpScriptTransform| null;
    }
    interface MediaStream {
        oninactive?: ((this: MediaStream, ev: Event) => void) | ((this: MediaStreamTrack, ev: Event) => void) | null;
    }
}
