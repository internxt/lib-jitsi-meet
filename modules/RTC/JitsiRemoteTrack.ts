import { getLogger } from '@jitsi/logger';

import JitsiConference from '../../JitsiConference';
import { JitsiTrackEvents } from '../../JitsiTrackEvents';
import { MediaType } from '../../service/RTC/MediaType';
import { RTCEvents } from '../../service/RTC/RTCEvents';
import { VideoType } from '../../service/RTC/VideoType';

import { createTtfmEvent } from '../../service/statistics/AnalyticsEvents';
import TrackStreamingStatusImpl, { TrackStreamingStatus } from '../connectivity/TrackStreamingStatus';
import Statistics from '../statistics/statistics';
import { isValidNumber } from '../util/MathUtil';

import RTCUtils from './RTCUtils';

import JitsiTrack from './JitsiTrack';  
import channels from '../../wasm/RTC/channels.js';
import { decode } from 'punycode';

let wasmChannels= null;
export async function getWasmModule() {
    if (!wasmChannels) {
        wasmChannels = channels({
            locateFile: (path) => {
                if (path.endsWith('.wasm')) {
                    return '/libs/channels.wasm';
                }
                return path;
            }
        });
    }
    return wasmChannels;
}
import RTC from './RTC';

const logger = getLogger('rtc:JitsiRemoteTrack');
const ort = require('onnxruntime-web');
ort.env.wasm.wasmPaths = '/libs/dist/';
let timer = false;

let ttfmTrackerAudioAttached = false;
let ttfmTrackerVideoAttached = false;

export let decodingSession = null;
/**
 * Loads the decoder model
 */
async function loadDecoder(){
    try{
        decodingSession = await ort.InferenceSession.create('/libs/models/Decoder.onnx', {freeDimensionOverrides: {
            batch: 1,
          }});
    }
    catch (error){
        console.error("Decoder model could not be loaded!: ", error);
    }
}
loadDecoder()

/**
 * Uses wasm binaries that transform HWC channel-order used by Javascript to CHW channel order used by python 
 * @param {data} data Javascript data container
 * @param {number} width image width
 * @param {number} height image height
 * @returns FloatA32Array
 */
export async function js2py(data,width,height){
    if(timer==true){
        console.time("TIMER loading wasm js2py decoder");
    }
    const Module = await getWasmModule();
    if(timer==true){
        console.timeEnd("TIMER loading wasm js2py decoder");
    }
    const ptr = Module._malloc(data.length);
    Module.HEAPU8.set(data, ptr);
    // Call the C++ reorder function
    if(timer==true){
        console.time("TIMER Applying js2py decoder");
    }
    Module._vjs2py(ptr, width, height);
    if(timer==true){
        console.timeEnd("TIMER Applying js2py decoder");
    }
    // Read back the result
    const result = Module.HEAPU8.subarray(ptr, ptr + data.length);
    Module._free(ptr);
    return Float32Array.from(result);
}

/**
 * Uses wasm binaries that transform CHW channel-order used by python to HWC channel order used by javascript 
 * @param {data} data Javascript data container
 * @param {data} tensorData Tensor data from ort module
 * @param {number} width image width
 * @param {number} height image height
 * @returns data
 */
export async function py2js(data,tensorData,width,height){
    if(timer==true){
        console.time("TIMER loading wasm py2js decoder")
    }
    const Module = await getWasmModule();
    if(timer==true){
        console.timeEnd("TIMER loading wasm py2js decoder")
    }
    const int8Tensor = Uint8ClampedArray.from(tensorData)
    const ptr = Module._malloc(int8Tensor.length);
    Module.HEAPU8.set(int8Tensor, ptr);
    // Call the C++ reorder function
    if(timer==true){
        console.time("TIMER applying py2js decoder");
    }
    Module._vpy2js(ptr, width, height);
    if(timer==true){
        console.timeEnd("TIMER applying py2js decoder");
    }
    // Read back the result
    const result = Module.HEAPU8.subarray(ptr, ptr + int8Tensor.length);
    data.set(result);
    Module._free(ptr);
    return data;
}

/**
 * List of container events that we are going to process. _onContainerEventHandler will be added as listener to the
 * container for every event in the list.
 */
const containerEvents = [ 'abort', 'canplaythrough', 'ended', 'error', 'stalled', 'suspend', 'waiting' ];

/* eslint-disable max-params */

/**
 * Represents a single media track (either audio or video).
 *
 * @noInheritDoc
 */
export default class JitsiRemoteTrack extends JitsiTrack {
    private _sourceName: string;
    private _trackStreamingStatus: Nullable<TrackStreamingStatus>;
    private _trackStreamingStatusImpl: Nullable<TrackStreamingStatusImpl>;

    /**
     * This holds the timestamp indicating when remote video track entered forwarded sources set. Track entering
     * forwardedSources will have streaming status restoring and when we start receiving video will become active,
     * but if video is not received for certain time {@link DEFAULT_RESTORING_TIMEOUT} that track streaming status
     * will become interrupted.
     */
    private _enteredForwardedSourcesTimestamp: Nullable<number>;
    private _containerHandlers: { [key: string]: (event: Event) => void; };
    private _rtc: RTC;
    private _muted: boolean;
    private _hasBeenMuted: boolean;
    private _ssrc: number;

    public ownerEndpointId: string;
    public isP2P: boolean;
    public rtcId: Nullable<string>;
    private _decodedStream;
    private _decodedTrack;

    /**
     * Creates new JitsiRemoteTrack instance.
     * @param {RTC} rtc the RTC service instance.
     * @param {JitsiConference} conference the conference to which this track
     *        belongs to
     * @param {string} ownerEndpointId the endpoint ID of the track owner
     * @param {MediaStream} stream WebRTC MediaStream, parent of the track
     * @param {MediaStreamTrack} track underlying WebRTC MediaStreamTrack for
     *        the new JitsiRemoteTrack
     * @param {MediaType} mediaType the type of the media
     * @param {VideoType} videoType the type of the video if applicable
     * @param {number} ssrc the SSRC number of the Media Stream
     * @param {boolean} muted the initial muted state
     * @param {boolean} isP2P indicates whether or not this track belongs to a
     * P2P session
     * @param {String} sourceName the source name signaled for the track
     * @throws {TypeError} if <tt>ssrc</tt> is not a number.
     */
    constructor(
            rtc: RTC,
            conference: JitsiConference,
            ownerEndpointId: string,
            stream: MediaStream,
            track: MediaStreamTrack,
            mediaType: MediaType,
            videoType: VideoType,
            ssrc: number,
            _muted: boolean,
            isP2P: boolean,
            sourceName: string) {
        super(
            conference,
            stream,
            track,
            () => {
                // Nothing to do if the track is inactive.
            },
            mediaType,
            videoType);
        this._rtc = rtc;

        // Prevent from mixing up type of SSRC which should be a number
        if (typeof ssrc !== 'number') {
            throw new TypeError(`SSRC ${ssrc} is not a number`);
        }
        this._ssrc = ssrc;
        this.ownerEndpointId = ownerEndpointId;
        this._muted = _muted;
        this.isP2P = isP2P;
        this._sourceName = sourceName;
        this._trackStreamingStatus = null;
        this._trackStreamingStatusImpl = null;
        this.rtcId = null;

        /**
         * This holds the timestamp indicating when remote video track entered forwarded sources set. Track entering
         * forwardedSources will have streaming status restoring and when we start receiving video will become active,
         * but if video is not received for certain time {@link DEFAULT_RESTORING_TIMEOUT} that track streaming status
         * will become interrupted.
         */
        this._enteredForwardedSourcesTimestamp = null;

        this.addEventListener = this.on = this._addEventListener.bind(this);
        this.removeEventListener = this.off = this._removeEventListener.bind(this);

        logger.debug(`New remote track created: ${this}`);

        // we want to mark whether the track has been ever muted
        // to detect ttfm events for startmuted conferences, as it can
        // significantly increase ttfm values
        this._hasBeenMuted = _muted;

        // Bind 'onmute' and 'onunmute' event handlers
        this._bindTrackHandlers();
        this._containerHandlers = {};
        containerEvents.forEach(event => {
            this._containerHandlers[event] = this._containerEventHandler.bind(this, event);
        });

        // Decoding streams the incoming videtrack
        this._decodedStream = null;
        this._decodedTrack = null;
    }

    /**
     * Returns decoded stream from camera stream
     * @returns MediaStream object
     */
    getDecodedStream()
    {
        return this._decodedStream;
    }

    /**
     * Returns decoded stream from camera stream
     * @returns Track object
     */
    getDecodedTrack()
    {
        return this._decodedTrack;
    }

    /**
     * Starts to decode the incoming images from the JVB
     */
    decodingRoutine(){
        try{
            // Creating canvas stream that will be attached to GUI
            const canvasDecoded =  document.createElement('canvas');
            this._decodedStream = canvasDecoded.captureStream();
            // Extracting track from canvas-sender
            this._decodedTrack = this._decodedStream.getVideoTracks()[0];
            const videoTrack = this.stream.getVideoTracks()[0];
            // Applying onnx model to incoming stream and saving the output in the canvas-sender
            this.applyONNXDecoder(videoTrack,canvasDecoded,this._muted);
        }
        catch(error){
            logger.error("Error on decoder phase: ", error);
        }
    }

    /**
     * Does the decoding phase of the incoming streams 
     * @param {*} videoTrack 
     * @param {*} canvasDecoded 
     */
    applyONNXDecoder(videoTrack,canvasDecoded,muted){
        // Frame-grabber to catch frames from the incoming stream  
        let imageCapture = new ImageCapture(videoTrack);
        // Setting up the aux canvas to paint the caught frames
        const canvasEncoded =  document.createElement('canvas');
        const ctxEncoded = canvasEncoded.getContext("2d",{willReadFrequently :true});
        const ctxDecoded = canvasDecoded.getContext('2d',{willReadFrequently :true});
        /*
         *  Decoded each frame from the incoming stream with decoded images, this function is repeated in loop
         */
        async function processFrame(){
            try{
                if(timer==true){
                    console.time("TIMER decoder");
                }
                // Getting the current size of the incoming stream
                const width = videoTrack.getSettings().width;
                const height = videoTrack.getSettings().height;
                // Adjusting the size of the aux canvas
                canvasEncoded.width = width;
                canvasEncoded.height = height;
                // Capturing a frame and painting it into the aux canvas
                const frame = await imageCapture.grabFrame();
                ctxEncoded.drawImage(frame, 0, 0, width, height);
                //Generating tensor from painted frame to be passed to the onnx model
                if(timer==true){
                    console.time("TIMER imageEncode get decoder");
                }
                const imageEncode = ctxEncoded.getImageData(0, 0, width, height);
                if(timer==true){
                    console.timeEnd("TIMER imageEncode get decoder");
                }
                const imageData = imageEncode.data;
                const channels = 4;
                // Channels are reordered as required by the onnx model 
                if(timer==true){
                    console.time("TIMER full js2py decoder");
                }
                let floatArray = await js2py(imageData,width,height);
                if(timer==true){
                    console.timeEnd("TIMER full js2py decoder");
                }
                // Applying the onnx model
                const tensor = new ort.Tensor("float32",floatArray,[1,channels,height,width]);
                const input = {
                    input: tensor
                };
                if(timer==true){
                    console.time("TIMER onnx decoder");
                }
                const results = await decodingSession.run(input);
                if(timer==true){
                    console.timeEnd("TIMER onnx decoder");
                }
                // Extracting output data from the onnx model
                const tensorData = results.output.data;
                // Resizing canvas that will be exported to GUI
                canvasDecoded.width = width*2;
                canvasDecoded.height = height*2;
                if(timer==true){
                    console.time("TIMER imageDataRestore create decoder");
                }
                const imageDataRestore = ctxDecoded.createImageData(canvasDecoded.width, canvasDecoded.height);
                if(timer==true){
                    console.timeEnd("TIMER imageDataRestore create decoder");
                }
                let dataRestore =  imageDataRestore.data;
                // Channels are reordered as required by javascript
                if(timer==true){
                    console.time("TIMER full py2js decoder");
                }
                dataRestore = await py2js(dataRestore,tensorData,canvasDecoded.width,canvasDecoded.height);
                if(timer==true){
                    console.timeEnd("TIMER full py2js decoder");
                }
                // Setting decoded image in the canvas-sender
                ctxDecoded.putImageData(imageDataRestore, 0, 0);
                if(timer==true){
                    console.timeEnd("TIMER decoder");
                }
            }
            catch(error){
                logger.info("Decoder failed! because: ",error);
            }
            if (muted == false){
                requestAnimationFrame(processFrame);
            }
        }
        processFrame();
    }

    /**
     * Attaches the MediaStream of this track to an HTML container.
     * Adds the container to the list of containers that are displaying the
     * track.
     *
     * @param container the HTML container which can be 'video' or 'audio'
     * element.
     * @param decode boolean to determine if the decoding session is used or not. 
     *
     * @returns {void}
     */
    attach(container, decode) {
        let result = Promise.resolve();
        if (this.type === MediaType.VIDEO) {
            if (this.videoType === VideoType.CAMERA){
                if (decode){
                    this.decodingRoutine();
                }
                if (this._decodedStream) {
                    this._onTrackAttach(container);
                    result = RTCUtils.attachMediaStream(container, this._decodedStream);
                }
                else if (this.stream) {
                    this._onTrackAttach(container);
                    result = RTCUtils.attachMediaStream(container, this.stream);
                }
                this.containers.push(container);
                this._attachTTFMTracker(container);
            }
        }
        else{
            if (this.stream) {
                this._onTrackAttach(container);
                result = RTCUtils.attachMediaStream(container, this.stream);
            }
            this.containers.push(container);
            this._attachTTFMTracker(container);
        }

        return result;
    }

    /* eslint-enable max-params */
    /**
     * Attaches the track handlers.
     *
     * @returns {void}
     */
    private _bindTrackHandlers(): void {
        this.track.addEventListener('mute', () => this._onTrackMute());
        this.track.addEventListener('unmute', () => this._onTrackUnmute());
        this.track.addEventListener('ended', () => {
            logger.debug(`"onended" event(${Date.now()}): ${this}`);
        });
    }

    /**
     * Overrides addEventListener method to init TrackStreamingStatus instance when there are listeners for the
     * {@link JitsiTrackEvents.TRACK_STREAMING_STATUS_CHANGED} event.
     *
     * @param {string} event - event name
     * @param {function} handler - event handler
     */
    private _addEventListener(event: string, handler: (...args: any[]) => void): void {
        super.addListener(event, handler);

        if (event === JitsiTrackEvents.TRACK_STREAMING_STATUS_CHANGED
            && this.listenerCount(JitsiTrackEvents.TRACK_STREAMING_STATUS_CHANGED)
            && !this._trackStreamingStatusImpl
        ) {
            this._initTrackStreamingStatus();
            logger.debug(`Initializing track streaming status: ${this._sourceName}`);
        }
    }

    /**
     * Overrides removeEventListener method to dispose TrackStreamingStatus instance.
     *
     * @param {string} event - event name
     * @param {function} handler - event handler
     */
    private _removeEventListener(event: string, handler: (...args: any[]) => void): void {
        super.removeListener(event, handler);

        if (event === JitsiTrackEvents.TRACK_STREAMING_STATUS_CHANGED
            && !this.listenerCount(JitsiTrackEvents.TRACK_STREAMING_STATUS_CHANGED)
        ) {
            this._disposeTrackStreamingStatus();
            logger.debug(`Disposing track streaming status: ${this._sourceName}`);
        }
    }

    /**
     * Callback invoked when the track is muted. Emits an event notifying
     * listeners of the mute event.
     *
     * @private
     * @returns {void}
     */
    private _onTrackMute(): void {
        logger.debug(`"onmute" event(${Date.now()}): ${this}`);

        // Ignore mute events that get fired on desktop tracks because of 0Hz screensharing introduced in Chromium.
        // The sender stops sending frames if the content of the captured window doesn't change resulting in the
        // receiver showing avatar instead of the shared content.
        if (this.videoType === VideoType.DESKTOP) {
            logger.debug('Ignoring mute event on desktop tracks.');

            return;
        }

        this._rtc.eventEmitter.emit(RTCEvents.REMOTE_TRACK_MUTE, this);
    }

    /**
     * Callback invoked when the track is unmuted. Emits an event notifying
     * listeners of the mute event.
     *
     * @private
     * @returns {void}
     */
    private _onTrackUnmute(): void {
        logger.debug(`"onunmute" event(${Date.now()}): ${this}`);

        this._rtc.eventEmitter.emit(RTCEvents.REMOTE_TRACK_UNMUTE, this);
    }

    /**
     * Handles track play events.
     */
    private _playCallback(): void {
        if (!this.conference.room) {
            return;
        }

        const type = this.isVideoTrack() ? 'video' : 'audio';

        const now = window.performance.now();

        logger.info(`(TIME) Render ${type}:\t`, now);
        this.conference.getConnectionTimes()[`${type}.render`] = now;

        // The conference can be started without calling GUM
        // FIXME if there would be a module for connection times this kind
        // of logic (gumDuration or ttfm) should end up there
        const gumStart = window.connectionTimes['obtainPermissions.start'];
        const gumEnd = window.connectionTimes['obtainPermissions.end'];
        const gumDuration
            = isValidNumber(gumEnd) && isValidNumber(gumStart) ? gumEnd - gumStart : 0;

        // Subtract the muc.joined-to-session-initiate duration because jicofo
        // waits until there are 2 participants to start Jingle sessions.
        const ttfm = now
            - (this.conference.getConnectionTimes()['session.initiate']
                - this.conference.getConnectionTimes()['muc.joined'])
            - gumDuration;

        this.conference.getConnectionTimes()[`${type}.ttfm`] = ttfm;
        logger.info(`(TIME) TTFM ${type}:\t`, ttfm);

        Statistics.sendAnalytics(createTtfmEvent(
            {
                'media_type': type,
                muted: this._hasBeenMuted,
                value: ttfm
            }));

    }

    /**
     * An event handler for events triggered by the attached container.
     *
     * @param {string} type - The type of the event.
     */
    private _containerEventHandler(type: string): void {
        logger.debug(`${type} handler was called for a container with attached ${this}`);
    }

    /**
     * Returns a string with a description of the current status of the track.
     *
     * @returns {string}
     */
    private _getStatus(): string {
        const { enabled, muted, readyState } = this.track;

        return `readyState: ${readyState}, muted: ${muted}, enabled: ${enabled}`;
    }

    /**
     * Initializes trackStreamingStatusImpl.
     */
    private _initTrackStreamingStatus(): void {
        const config = this.conference.options.config;

        this._trackStreamingStatus = TrackStreamingStatus.ACTIVE;

        this._trackStreamingStatusImpl = new TrackStreamingStatusImpl(
            this._rtc,
            this.conference,
            this,
            {
                // These options are not public API, leaving it here only as an entry point through config for
                // tuning up purposes. Default values should be adjusted as soon as optimal values are discovered.
                outOfForwardedSourcesTimeout: config._peerConnStatusOutOfLastNTimeout,
                p2pRtcMuteTimeout: config._p2pConnStatusRtcMuteTimeout,
                rtcMuteTimeout: config._peerConnStatusRtcMuteTimeout
            });

        this._trackStreamingStatusImpl.init();

        // In some edge cases, both browser 'unmute' and bridge's forwarded sources events are received before a
        // LargeVideoUpdate is scheduled for auto-pinning a new screenshare track. If there are no layout changes and
        // no further track events are received for the SS track, a black tile will be displayed for screenshare on
        // stage. Fire a TRACK_STREAMING_STATUS_CHANGED event if the media is already being received for the remote
        // track to prevent this from happening.
        !this._trackStreamingStatusImpl.isVideoTrackFrozen()
            && this._rtc.eventEmitter.emit(
                JitsiTrackEvents.TRACK_STREAMING_STATUS_CHANGED,
                this,
                this._trackStreamingStatus);
    }

    /**
     * Disposes trackStreamingStatusImpl and clears trackStreamingStatus.
     */
    private _disposeTrackStreamingStatus(): void {
        if (this._trackStreamingStatusImpl) {
            this._trackStreamingStatusImpl.dispose();
            this._trackStreamingStatusImpl = null;
            this._trackStreamingStatus = null;
        }
    }

    /**
     * Called when the track has been attached to a new container.
     *
     * @param {HTMLElement} container the HTML container which can be 'video' or 'audio' element.
     * @internal
     */
    protected override _onTrackAttach(container: HTMLElement): void {
        containerEvents.forEach(event => {
            container.addEventListener(event, this._containerHandlers[event]);
        });
    }

    /**
     * Called when the track has been detached from a container.
     *
     * @param {HTMLElement} container the HTML container which can be 'video' or 'audio' element.
     * @internal
     */
    protected override _onTrackDetach(container: HTMLElement): void {
        containerEvents.forEach(event => {
            container.removeEventListener(event, this._containerHandlers[event]);
        });
    }

    /**
     * Attach time to first media tracker only if there is conference and only
     * for the first element.
     * @param container the HTML container which can be 'video' or 'audio'
     * element.
     */
    protected override _attachTTFMTracker(container: HTMLElement): void {
        if ((ttfmTrackerAudioAttached && this.isAudioTrack())
                || (ttfmTrackerVideoAttached && this.isVideoTrack())) {
            return;
        }

        if (this.isAudioTrack()) {
            ttfmTrackerAudioAttached = true;
        }
        if (this.isVideoTrack()) {
            ttfmTrackerVideoAttached = true;
        }

        container.addEventListener('canplay', this._playCallback.bind(this));
    }

    /**
     * Changes the video type of the track.
     *
     * @param {string} type - The new video type("camera", "desktop").
     * @internal
     */
    _setVideoType(type: VideoType): void {
        if (this.videoType === type) {
            return;
        }
        this.videoType = type;
        this.emit(JitsiTrackEvents.TRACK_VIDEOTYPE_CHANGED, type);
    }

    /**
     * Updates track's streaming status.
     *
     * @param {string} state the current track streaming state. {@link TrackStreamingStatus}.
     * @internal
     */
    _setTrackStreamingStatus(status: TrackStreamingStatus): void {
        this._trackStreamingStatus = status;
    }

    /**
     * Clears the timestamp of when the track entered forwarded sources.
     * @internal
     */
    _clearEnteredForwardedSourcesTimestamp(): void {
        this._enteredForwardedSourcesTimestamp = null;
    }

    /**
     * Updates the timestamp of when the track entered forwarded sources.
     *
     * @param {number} timestamp the time in millis
     * @internal
     */
    _setEnteredForwardedSourcesTimestamp(timestamp: number): void {
        this._enteredForwardedSourcesTimestamp = timestamp;
    }

    /**
     * Returns the timestamp of when the track entered forwarded sources.
     *
     * @returns {number} the time in millis
     * @internal
     */
    _getEnteredForwardedSourcesTimestamp(): number | null {
        return this._enteredForwardedSourcesTimestamp;
    }

    /**
     * Removes attached event listeners and dispose TrackStreamingStatus .
     *
     * @returns {Promise}
     */
    override async dispose(): Promise<void> {
        if (this.disposed) {
            return;
        }

        this._disposeTrackStreamingStatus();

        return super.dispose();
    }

    /**
     * Sets current muted status and fires an events for the change.
     * @param value the muted status.
     * @internal
     */
    setMute(value: boolean): void {
        if (this._muted === value) {
            return;
        }

        if (value) {
            this._hasBeenMuted = true;
        }

        // we can have a fake video stream
        if (this.stream) {
            this.stream.muted = value;
        }

        this._muted = value;

        logger.info(`Mute ${this}: ${value}`);
        this.emit(JitsiTrackEvents.TRACK_MUTE_CHANGED, this);
    }

    /**
     * Returns the current muted status of the track.
     * @returns {boolean|*|JitsiRemoteTrack.muted} <tt>true</tt> if the track is
     * muted and <tt>false</tt> otherwise.
     */
    override isMuted(): boolean {
        return this._muted;
    }

    /**
     * Returns the participant id which owns the track.
     *
     * @returns {string} the id of the participants. It corresponds to the
     * Colibri endpoint id/MUC nickname in case of Jitsi-meet.
     */
    getParticipantId(): string {
        return this.ownerEndpointId;
    }

    /**
     * Returns the synchronization source identifier (SSRC) of this remote
     * track.
     *
     * @override
     * @returns {number} the SSRC of this remote track.
     */
    override getSsrc() {
        return this._ssrc;
    }


    /**
     * Returns the tracks source name
     *
     * @override
     * @returns {string} the track's source name
     */
    override getSourceName(): string {
        return this._sourceName;
    }

    /**
     * Update the properties when the track is remapped to another source.
     *
     * @param {string} owner The endpoint ID of the new owner.
     * @internal
     */
    setOwner(owner: string): void {
        this.ownerEndpointId = owner;
    }

    /**
     * Sets the name of the source associated with the remote track.
     *
     * @override
     * @param {string} name - The source name to be associated with the track.
     * @internal
     */
    override setSourceName(name: string): void {
        this._sourceName = name;
    }

    /**
     * Returns track's streaming status.
     *
     * @returns {string} the streaming status <tt>TrackStreamingStatus</tt> of the track. Returns null
     * if trackStreamingStatusImpl hasn't been initialized.
     *
     * {@link TrackStreamingStatus}.
     */
    getTrackStreamingStatus(): Nullable<TrackStreamingStatus> {
        return this._trackStreamingStatus;
    }

    /**
     * Creates a text representation of this remote track instance.
     * @return {string}
     */
    override toString(): string {
        return `RemoteTrack[userID: ${this.getParticipantId()}, type: ${this.getType()}, ssrc: ${
            this.getSsrc()}, p2p: ${this.isP2P}, sourceName: ${this._sourceName}, status: {${this._getStatus()}}]`;
    }
}
