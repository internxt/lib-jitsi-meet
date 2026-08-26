import JitsiRemoteTrack, { loadDecoder, decodingSession } from '../modules/RTC/JitsiRemoteTrack';
import { MediaType } from '../service/RTC/MediaType';
import { VideoType } from '../service/RTC/VideoType';
import RTC from '../modules/RTC/RTC';
import { createMockConference } from './mocks';
import RTCUtils from '../modules/RTC/RTCUtils.js';

const KARMA_MODEL_PATH = '/base/models/RTC/Decoder.onnx';

function makeFakeVideoStream(width = 80, height = 60): { stream: MediaStream; stop: () => void } {
    const canvas = document.createElement('canvas');

    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d')!;

    let frame = 0;
    const id = setInterval(() => {
        const imageData = ctx.createImageData(width, height);

        for (let i = 0; i < imageData.data.length; i += 4) {
            const x = (i / 4) % width;
            const y = Math.floor(i / 4 / width);

            imageData.data[i]     = (x * 3 + frame) % 256;   
            imageData.data[i + 1] = (y * 3 + frame * 2) % 256;
            imageData.data[i + 2] = (x + y + frame) % 256;
            imageData.data[i + 3] = 255;
        }
        ctx.putImageData(imageData, 0, 0);
        frame++;
    }, 33);

    return {
        stream: canvas.captureStream(30),
        stop: () => clearInterval(id),
    };
}

function makeTrack(stream: MediaStream): JitsiRemoteTrack {
    const videoTrack = stream.getVideoTracks()[0];
    const conferenceMock = createMockConference();
    const rtc =  new RTC(conferenceMock);
    

    return new JitsiRemoteTrack(
        rtc,
        conferenceMock,
        'endpoint-1',
        stream,
        videoTrack,
        MediaType.VIDEO,
        VideoType.CAMERA,
        12345,
        false,
        false,
        'source-1',
    );
}

function waitUntil(predicate: () => boolean, timeoutMs = 2_000, intervalMs = 100): Promise<void> {
    return new Promise((resolve, reject) => {
        const start = Date.now();
        const id = setInterval(() => {
            if (predicate()) {
                clearInterval(id);
                resolve();
            } else if (Date.now() - start > timeoutMs) {
                clearInterval(id);
                reject(new Error(`waitUntil timed out after ${timeoutMs} ms`));
            }
        }, intervalMs);
    });
}

describe('JitsiRemoteTrack decoder', () => {
    let stream: MediaStream;
    let track: JitsiRemoteTrack;
    let container: HTMLVideoElement;

    let stopStream: () => void;

    beforeAll(async () => {
        await loadDecoder(KARMA_MODEL_PATH);
        expect((JitsiRemoteTrack as any).decodingSession).not.toBeNull();
    }, 1_000);


    beforeEach(() => {
        const fakeStream = makeFakeVideoStream(80, 60);
        stream = fakeStream.stream;
        stopStream = fakeStream.stop;
        track = makeTrack(stream);
        container = document.createElement('video');
        container.muted = true;
        document.body.appendChild(container);
    });

    afterEach(async () => {
        stopStream();
        await track.dispose();
        container.remove();
        stream.getTracks().forEach(t => t.stop());
    });

    describe('memory management', () => {

        it('sets variable when decoder is activated', async () => {
            track.increaseResolution(container);

            await waitUntil(() => track.isDecoderOn()=== true);
            expect((track as any)._animationFrameId).toBeGreaterThan(0);
            expect(track.isDecoderOn()).toBeTrue();
            expect((track as any).inputTensor !== null).toBeTrue();
            expect((track as any).shouldDecode).toBeTrue();
            expect((track as any).dataOutput !== null).toBeTrue();
            expect((track as any).inputBuffer !== null).toBeTrue();
            expect((track as any).height !== 0).toBeTrue();
            expect((track as any).width !== 0).toBeTrue();

        });

        it('clear all variables after clean up is called', async () => {
            track.increaseResolution(container);
            await waitUntil(() => track.isDecoderOn()=== true);

            await track.dispose();

            expect((track as any)._animationFrameId).toBeNull();
            expect(track.isDecoderOn()).toBeFalse();
            expect((track as any).inputTensor).toBeNull();
            expect((track as any).shouldDecode).not.toBeTrue();
            expect((track as any).height === 0).toBeTrue();
            expect((track as any).width === 0).toBeTrue();
            expect((track as any)._rawVideo).toBeNull();

        });

        it('calls dispose() for inputTensor in track dispose()', async () => {
            track.increaseResolution(container);
            await waitUntil(() => track.isDecoderOn()=== true);

            const spy = spyOn((track as any).inputTensor, 'dispose').and.callThrough();

            await track.dispose();

            expect(spy).toHaveBeenCalled();
        });

        it('stops all _decodedStream tracks after dispose()', async () => {
            track.increaseResolution(container);
            await waitUntil(() => track.isDecoderOn()=== true);

            const decodedStream: MediaStream = (track as any)._decodedStream;
            const innerTracks = decodedStream.getTracks();

            await track.dispose();

            innerTracks.forEach(t => {
                expect(t.readyState).toBe('ended');
            });
            expect((track as any)._decodedStream).toBeNull();
        });

        it('reallocates tensor only when frame dimensions change', async () => {
            track.increaseResolution(container);
            await waitUntil(() => track.isDecoderOn()=== true);

            const firstTensor = (track as any).inputTensor;

            await new Promise(r => setTimeout(r, 500));
            expect((track as any).inputTensor).toBe(firstTensor);
        });

        it('does not start a new frame while the previous one is still being processed', async () => {
            const runSpy = spyOn(decodingSession, 'run').and.callThrough();
            track.increaseResolution(container);
            await waitUntil(() => track.isDecoderOn() === true);
            await waitUntil(() => track.isProcessingFrame === false);

            const callsBefore = runSpy.calls.count();
            track.isProcessingFrame = true;
            
            await new Promise(r => setTimeout(r, 300));

            expect(runSpy.calls.count()).toBe(callsBefore);
            track.isProcessingFrame = false;
            await waitUntil(() => track.isProcessingFrame === false)

        });

        it('disposes previous inputTensor before allocating a new one on dimension change', async () => {
            track.increaseResolution(container);
            await waitUntil(() => track.isDecoderOn() === true);

            const firstTensor = (track as any).inputTensor;
            const disposeSpy = spyOn(firstTensor, 'dispose').and.callThrough();

            // Trigger dimension change
            const { stream: differentResStream, stop } = makeFakeVideoStream(160, 120);

            (track as any)._rawVideo.srcObject = differentResStream;

            await waitUntil(() => (track as any).inputTensor !== firstTensor);

            expect(disposeSpy).toHaveBeenCalled();

            await track.dispose();
            stop();
        });
    });


    describe('if decoder fails, back to the original track', () => {

        it('if decoder suddenly fails, turns it off and uses original stream', async () => {
            track.increaseResolution(container);
            await waitUntil(() => track.isDecoderOn()=== true);
            const ort = require('onnxruntime-web/wasm');
            const badTensor = new ort.Tensor('float32', new Float32Array(0), [ 0, 0, 0, 0 ]);

            (track as any).inputTensor = badTensor;

            await waitUntil(() => track.isDecoderOn()=== false);

            expect((track as any).shouldDecode).toBe(false);
            expect(track.isProcessingFrame).toBe(false);
            expect(track.isDecoderOn()).toBe(false);
            expect((track as any)._animationFrameId).not.toBeNull();
        });

        it('does not attach the decoded stream at all if decoder fails on the first frame', async () => {

            const runSpy = spyOn(decodingSession, 'run').and.rejectWith(new Error('injected failure'));

            track.increaseResolution(container);
            await waitUntil(() => runSpy.calls.count() >= 1);
        

            expect((track as any).shouldDecode).toBe(false);
            expect(track.isProcessingFrame).toBe(false);
            expect(track.isDecoderOn()).toBe(false);
            expect((track as any)._animationFrameId).not.toBeNull();

        });

        
        it('turns decoder off and falls back to original stream when resolution rises above 240p', async () => {
            track.increaseResolution(container);
            await waitUntil(() => track.isDecoderOn() === true);

            const { stream: highResStream, stop: stopHighRes } = makeFakeVideoStream(640, 480);

            (track as any)._rawVideo.srcObject = highResStream;

            await waitUntil(() => track.isDecoderOn() === false);

            expect((track as any).shouldDecode).toBe(false);
            expect(track.isDecoderOn()).toBe(false);

            stopHighRes();
        });

        it('If processFrame fails, the loop keeps working and tries the next frame', async () => {

            track.increaseResolution(container);
            await waitUntil(() => track.isDecoderOn() === true);

            const runSpy = spyOn(decodingSession, 'run').and.rejectWith(new Error('injected failure'));

            await waitUntil(() => runSpy.calls.count() >= 2, 4000);

            expect((track as any)._animationFrameId).not.toBeNull();
            expect((track as any).shouldDecode).toBe(false);
            expect(track.isDecoderOn()).toBe(false);
        });
    });
});