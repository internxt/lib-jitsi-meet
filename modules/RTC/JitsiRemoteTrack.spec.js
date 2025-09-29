import JitsiRemoteTrack from './JitsiRemoteTrack';
import { MediaType } from '../../service/RTC/MediaType';
import { VideoType } from '../../service/RTC/VideoType';
const ort = require('onnxruntime-web');
const jrt = require('./JitsiRemoteTrack');

describe("Lets test the ONNX decoding model and routine performance",()=>{

    it("The ONNX decoding session should be loaded succesfully ",() =>{
        expect(jrt.decodingSession).not.toBeNull();
    });
    it("The ONNX decoding session must increase the size of an input image", async ()=>{
        const decoding_session = jrt.decodingSession;
        let results = null;
        const width  = 256;
        const height = 128;
        const channels = 4;
        const dummyArray = new Float32Array(width*height*channels); 
        for(let i=0; i< width*height*channels;i++){
            dummyArray[i] = (i % 256);
        }
        const dummyTensor = new ort.Tensor("float32",dummyArray,[1,channels,height,width]);
        const inputDecoder = { 
            input: dummyTensor
        };
        results = await decoding_session.run(inputDecoder);
        expect(results).not.toBeNull();
        const tensorOutput = results.output;
        expect(tensorOutput.size).toBe(width*height*4*4);
    });
    it("The wasm module to exchange channels in tensors must be loaded successfully",()=>{
        let wasmodule = null;
        wasmodule = jrt.getWasmModule();
        expect(wasmodule).not.toBeNull();
    });
    it("The py2js channels function must return tensors of the same size as the input must not be equal",async ()=>{
        const width  = 256;
        const height = 128;
        const channels = 4;
        const dummyArray = new Float32Array(width*height*channels); 
        for(let i=0; i< width*height*channels;i++){
            dummyArray[i] = (i % 256);
        }
        const dummyTensor = new ort.Tensor("float32",dummyArray,[1,channels,height,width]);
        const canvasDummy = document.createElement('canvas');
        const ctxDummy = canvasDummy.getContext('2d',{willReadFrequently :true});
        canvasDummy.width = width;
        canvasDummy.height = height;
        const imageDummy = ctxDummy.getImageData(0, 0, width, height);
        const dummyData = imageDummy.data;
        let outputpy2js = await jrt.py2js(dummyData,dummyTensor,width,height);
        const outputArraypy2js = Float32Array.from(outputpy2js);
        const outputTensorpy2js = new ort.Tensor("float32",outputArraypy2js,[1,channels,height,width]);
        expect(dummyTensor.size).toBe(outputTensorpy2js.size);
        expect(dummyTensor.data).not.toBe(outputTensorpy2js.data);
    });
    it("The js2py channels function must return tensors of the same size as the input must not be equal",async ()=>{
        const width  = 256;
        const height = 128;
        const channels = 4;
        const dummyArray = new Float32Array(width*height*channels); 
        for(let i=0; i< width*height*channels;i++){
            dummyArray[i] = (i % 256);
        }
        const dummyTensor = new ort.Tensor("float32",dummyArray,[1,channels,height,width]);
        let outputjs2py = await jrt.js2py(dummyTensor.data,width,height);
        const outputTensorjs2py = new ort.Tensor("float32",outputjs2py,[1,channels,height,width]);
        expect(dummyTensor.size).toBe(outputTensorjs2py.size);
        expect(dummyTensor.data).not.toBe(outputTensorjs2py.data);
    })
})

describe("Let's test a JitsiLocalTrack encoding capabilities", () =>{
    it("If the stream contains audio it should not start the encoding model and therefore the encoding track and stream must be null", ()=>{
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
            const dummyjrt = new JitsiRemoteTrack(null,null,1,stream,track,MediaType.AUDIO,undefined,1,false,true,"audio");
            const contVideo = document.createElement("audio");
            dummyjrt.attach(contVideo);
            expect(dummyjrt.getDecodedStream()).toBeNull();
            expect(dummyjrt.getDecodedTrack()).toBeNull();}
    })
    it("If the stream contains video from the desktop it should not start the encoding track and stream must be null", async ()=>{
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
            const dummyjrt = new JitsiRemoteTrack(null,null,1,stream,track,MediaType.VIDEO,VideoType.DESKTOP,1,false,true,"video");
            const contVideo = document.createElement("video");
            dummyjrt.attach(contVideo);
            expect(dummyjrt.getDecodedStream()).toBeNull();
            expect(dummyjrt.getDecodedTrack()).toBeNull();
        };
    })
    it("If the stream contains video from a videocam it should start the encoding track and stream must not be null", ()=>{
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
            const dummyjrt = new JitsiRemoteTrack(null,null,1,stream,track,MediaType.VIDEO,VideoType.CAMERA,1,false,true,"video");
        const contVideo = document.createElement("video");
        dummyjrt.attach(contVideo);
        expect(dummyjrt.ENCOD).not.toBeNull();
        expect(dummyjrt.getEncodedTrack()).not.toBeNull();
        };
    })
})

