export {};

declare global {
    interface Window {
        connectionTimes: any;
        Olm: Window.Olm;
        RTCTransformEvent: Window.RTCTransformEvent;
        RTCRtpScriptTransform: Window.RTCRtpScriptTransform;
        onrtctransform: Window.onrtctransform;
    }

    declare class RTCRtpScriptTransform {
        constructor(worker: Worker, options?: any);
    }
}
