export {};

declare global {
    interface Window {
        connectionTimes: any;
        RTCTransformEvent: Window.RTCTransformEvent;
        RTCRtpScriptTransform: Window.RTCRtpScriptTransform;
        onrtctransform: Window.onrtctransform;
    }

    declare class RTCRtpScriptTransform {
        constructor(worker: Worker, options?: any);
    }
}
