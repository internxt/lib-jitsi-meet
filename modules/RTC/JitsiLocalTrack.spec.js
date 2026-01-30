/* eslint-disable max-len */
import JitsiLocalTrack from './JitsiLocalTrack';
import { MediaType } from '../../service/RTC/MediaType';
import { VideoType } from '../../service/RTC/VideoType';
const ort = require('onnxruntime-web');
const jlt = require('./JitsiLocalTrack');

describe("Lets test the ONNX encoding model and routine performance",()=>{

    it("The ONNX encoding session should be loaded succesfully ",() =>{
        expect(jlt.encodingSession).not.toBeNull();
    });
    it("The ONNX encoding session must reduce the size of an input image", async ()=>{
        const encoding_session = jlt.encodingSession;
        let results = null;
        const width  = 256;
        const height = 128;
        const channels = 4;
        const dummyArray = new Float32Array(width*height*channels); 
        for(let i=0; i< width*height*channels;i++){
            dummyArray[i] = (i % 256);
        }
        const dummyTensor = new ort.Tensor("float32",dummyArray,[1,channels,height,width]);
        const inputEncoder = { 
            input: dummyTensor
        };
        results = await encoding_session.run(inputEncoder);
        expect(results).not.toBeNull();
        const tensorOutput = results.output;
        expect(tensorOutput.size).toBe(width*height);
    });
})

describe("Let's test a JitsiLocalTrack encoding capabilities", () =>{
    it("If the stream contains audio it should not start the encoding model and therefore the encoding track and stream must be null", ()=>{
        const constraints_audio = {
            autoGainControl: true,
            echoCancellation: true,
            noiseSuppression: true
        };
        let stream = null;
        const video = document.createElement("video");
        video.setAttribute('id', 'video-mock');
        video.setAttribute("src", 'https://shattereddisk.github.io/rickroll/rickroll.mp4');
        video.setAttribute("crossorigin", "anonymous");
        video.setAttribute("controls", "");
        video.oncanplay = () => {
            stream = video.captureStream();
            navigator.mediaDevices.getUserMedia = () => Promise.resolve(stream);
            const track = stream.getAudioTracks()[0];
            const dummyjlt = new JitsiLocalTrack({
                constraints: constraints_audio,
                deviceId: "default",
                facingMode: undefined,
                mediaType: MediaType.AUDIO,
                rtcId: 1,
                sourceId: undefined,
                sourceType: undefined,
                stream: stream,
                track: track,
                videoType: null,
                effects : []});
            expect(dummyjlt.getEncodedStream()).toBeNull();
            expect(dummyjlt.getEncodedTrack()).toBeNull();}
    })
    it("If the stream contains video from the desktop it should not start the encoding track and stream must be null", async ()=>{
        const constraints_video = {
            height: {
                ideal: 720,
                max: 720,
                min: 180
            },
            width: {
                ideal: 1280,
                max: 1280,
                min: 320
            },
            frameRate: {
                min: 15,
                max: 30
            }
        }
        let stream = null;
        const video = document.createElement("video");
        video.setAttribute('id', 'video-mock');
        video.setAttribute("src", 'https://shattereddisk.github.io/rickroll/rickroll.mp4');
        video.setAttribute("crossorigin", "anonymous");
        video.setAttribute("controls", "");
        video.oncanplay = () => {
            stream = video.captureStream();
            navigator.mediaDevices.getUserMedia = () => Promise.resolve(stream);
            const track = stream.getVideoTracks()[0];
            const dummyjlt = new JitsiLocalTrack({
            constraints: constraints_video,
            deviceId: "default",
            facingMode: undefined,
            mediaType: MediaType.VIDEO,
            rtcId: 1,
            sourceId: undefined,
            sourceType: undefined,
            stream: stream,
            track: track,
            videoType: VideoType.DESKTOP,
            effects : []});
        expect(dummyjlt.getEncodedStream()).toBeNull();
        expect(dummyjlt.getEncodedTrack()).toBeNull();
        };
    })
    it("If the stream contains video from a videocam it should start the encoding track and stream must not be null", ()=>{
        const constraints_video = {
            height: {
                ideal: 720,
                max: 720,
                min: 180
            },
            width: {
                ideal: 1280,
                max: 1280,
                min: 320
            },
            frameRate: {
                min: 15,
                max: 30
            }
        }
        let stream = null;
        const video = document.createElement("video");
        video.setAttribute('id', 'video-mock');
        video.setAttribute("src", 'https://shattereddisk.github.io/rickroll/rickroll.mp4');
        video.setAttribute("crossorigin", "anonymous");
        video.setAttribute("controls", "");
        video.oncanplay = () => {
            stream = video.captureStream();
            navigator.mediaDevices.getUserMedia = () => Promise.resolve(stream);
            const track = stream.getVideoTracks()[0];
            const dummyjlt = new JitsiLocalTrack({
            constraints: constraints_video,
            deviceId: "default",
            facingMode: undefined,
            mediaType: MediaType.VIDEO,
            rtcId: 1,
            sourceId: undefined,
            sourceType: undefined,
            stream: stream,
            track: track,
            videoType: VideoType.CAMERA,
            effects : []});
        expect(dummyjlt.getEncodedStream()).not.toBeNull();
        expect(dummyjlt.getEncodedTrack()).not.toBeNull();
        };
    })
})
