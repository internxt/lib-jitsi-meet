import { setupWorker } from "../modules/e2ee/Worker";
import { ManagedKeyHandler } from "../modules/e2ee/ManagedKeyHandler";
import JitsiParticipant from "../JitsiParticipant";
import JitsiConference from "../JitsiConference.js";
import RTC from "../modules/RTC/RTC.js";
import EventEmitter from "../modules/util/EventEmitter";
import * as JitsiConferenceEvents from "../JitsiConferenceEvents";

import { mock, instance, when, anything } from "ts-mockito";

export function delay(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

export class WorkerMock {
    public onmessage: ((event: MessageEvent) => void) | null = null;
    public onerror: ((event: Event) => void) | null = null;
    private readonly _fakeWorkerSelf: {
        postMessage: (data: any) => void;
        onmessage: ((event: MessageEvent) => void) | null;
    };

    constructor(_scriptUrl: string, _options?: WorkerOptions) {
        this._fakeWorkerSelf = {
            postMessage: (data: any) => {
                setTimeout(() => {
                    this.onmessage?.({ data } as MessageEvent);
                }, 0);
            },
            onmessage: null,
        };
        (globalThis as any).self = this._fakeWorkerSelf;
        const originalSelf = globalThis.self;
        setupWorker(this._fakeWorkerSelf);
        (globalThis as any).self = originalSelf;
    }
    postMessage(data: any) {
        this._fakeWorkerSelf.onmessage?.({ data } as MessageEvent);
    }
}

export class XmppServerMock {
    private readonly listeners = new Map<string, ManagedKeyHandler>();
    private readonly participants = new Map<string, JitsiParticipant>();
    private readonly sasMap = new Map<string, string[]>();
    private e2e: boolean = false;

    createMockParticipant(participantId: string): JitsiParticipant {
        const mockParticipant = mock(JitsiParticipant);
        when(mockParticipant.getId()).thenReturn(participantId);
        when(mockParticipant.hasFeature(anything())).thenReturn(true);
        const participant = instance(mockParticipant);
        return participant;
    }

    setSas(id: string, sas: string[]) {
        this.sasMap.set(id, sas);
    }

    getSas(id: string): string[] {
        return this.sasMap.get(id);
    }

    getParticipantsFor(id: string): JitsiParticipant[] {
        const list: JitsiParticipant[] = [];
        this.participants.forEach((participant, pId) => {
            if (id !== pId) {
                list.push(participant);
            }
        });
        return list;
    }

    async enableE2E() {
        this.e2e = true;
        for (const [_, keyHandler] of this.listeners) {
            await keyHandler.setEnabled(true);
            expect(keyHandler.isEnabled()).toBe(true);
            expect(keyHandler._olmAdapter.isInitialized()).toBe(true);
        }
    }

    diableE2E() {
        this.e2e = false;
        this.listeners.forEach((keyHandler, _id) => {
            keyHandler.setEnabled(false);
        });
    }

    async userJoined(keyHandler: ManagedKeyHandler) {
        if (this.e2e) {
            keyHandler.setEnabled(true);
        }
        const pId = keyHandler.conference.myUserId();
        if (!this.listeners.has(pId)) {
            const list: string[] = [];
            this.listeners.forEach((existingHandler, id) => {
                existingHandler._onParticipantJoined(pId);
                list.push(id);
            });
            this.listeners.set(pId, keyHandler);

            for (const id of list) {
                keyHandler._onParticipantJoined(id);
            }

            const participant = this.createMockParticipant(pId);
            this.participants.set(pId, participant);
        }
    }

    userLeft(pId: string) {
        this.participants.delete(pId);
        this.listeners.forEach((keyHandler, id) => {
            if (id !== pId) {
                keyHandler._onParticipantLeft(pId);
            }
        });
    }

    sendMessage(myId: string, pId: string, payload: any) {
        this.listeners.forEach((keyHandler, id) => {
            if (id === pId) {
                keyHandler._onEndpointMessageReceived(
                    this.participants.get(myId),
                    payload,
                );
            }
        });
    }
}

export async function createMockManagedKeyHandler(
    xmppServerMock: XmppServerMock,
): Promise<{
    id: string;
    keyHandler: ManagedKeyHandler;
}> {
    const id = new Date().getTime().toString().slice(-8);

    const conferenceMock = mock<JitsiConference>();

    when(conferenceMock.myUserId()).thenReturn(id);

    const mockRTC = new RTC(conferenceMock);
    when(conferenceMock.rtc).thenReturn(mockRTC);

    const eventEmitterMock = mock<EventEmitter>();

    when(eventEmitterMock.emit(anything(), anything())).thenCall(
        (event, sas) => {
            if (event === JitsiConferenceEvents.E2EE_SAS_AVAILABLE) {
                xmppServerMock.setSas(id, sas);
            }
        },
    );

    when(eventEmitterMock.emit(anything())).thenCall((event) => {
        if (event === JitsiConferenceEvents.CONFERENCE_JOINED) {
            keyHandler._conferenceJoined = true;
        }
    });

    when(conferenceMock.eventEmitter).thenReturn(instance(eventEmitterMock));

    const eventHandlers = new Map<string, Function[]>();
    when(conferenceMock.on(anything(), anything())).thenCall(
        (eventName, handler) => {
            if (!eventHandlers.has(eventName)) {
                eventHandlers.set(eventName, []);
            }
            eventHandlers.get(eventName)?.push(handler);
            return conferenceMock;
        },
    );
    when(conferenceMock.getParticipants()).thenCall(() => {
        return xmppServerMock.getParticipantsFor(id);
    });

    when(conferenceMock.sendMessage(anything(), anything())).thenCall(
        (payload, pId) => {
            xmppServerMock.sendMessage(id, pId, payload);
        },
    );

    const conference = instance(conferenceMock);
    const keyHandler = new ManagedKeyHandler(conference);
    await delay(100);
    conference.eventEmitter.emit(JitsiConferenceEvents.CONFERENCE_JOINED);

    return { id, keyHandler };
}
