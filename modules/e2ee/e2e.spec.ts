import { ManagedKeyHandler } from "../../modules/e2ee/ManagedKeyHandler";
import JitsiConference from "../../JitsiConference";
import JitsiParticipant from "../../JitsiParticipant";

import { mock, instance, when, anything, verify, spy } from "ts-mockito";
import initKyber from "@dashlane/pqc-kem-kyber512-browser/dist/pqc-kem-kyber512.js";
import initOlm from "vodozemac-wasm/javascript/pkg/vodozemac.js";
import RTC from "../RTC/RTC";

import { OlmAdapter } from "./OlmAdapter";
import EventEmitter from "../util/EventEmitter";
import * as JitsiConferenceEvents from "../../JitsiConferenceEvents";

function delay(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

class WorkerMock {
  public onmessage: ((event: MessageEvent) => void) | null = null;
  public onerror: ((event: Event) => void) | null = null;
  private readonly _fakeWorkerSelf: any;
  constructor(_scriptUrl: string, _options?: WorkerOptions) {
    const originalSelf = globalThis.self;
    const workerInstance = this;
   const interceptedPostMessage = function(data: any) {
    setTimeout(() => {
      workerInstance.onmessage?.({ data } as MessageEvent);
    }, 0);
  };
    this._fakeWorkerSelf = originalSelf;
    this._fakeWorkerSelf.postMessage = interceptedPostMessage;
    (globalThis as any).self = this._fakeWorkerSelf;
    require("./Worker");
    (globalThis as any).self = originalSelf;
  }
  postMessage(data: any) {
    setTimeout(() => {
      this._fakeWorkerSelf.onmessage?.({ data } as MessageEvent);
    }, 0);
  }
  terminate() {
    // Optional: simulate cleanup
  }
}
  
describe("Test e2e module", () => {
    beforeAll(async () => {
        const kyberPath =
            "/base/node_modules/@dashlane/pqc-kem-kyber512-browser/dist/pqc-kem-kyber512.wasm";
        await initKyber(kyberPath);
        const wasmPath =
            "/base/node_modules/vodozemac-wasm/javascript/pkg/vodozemac_bg.wasm";
        await initOlm(wasmPath);
    });

    beforeEach(() => { 
      (window as any).Worker = WorkerMock;
    });

    const xmppServerMock = {
        listeners: new Map<string, ManagedKeyHandler>(),
        participants: new Map<string, JitsiParticipant>(),
        sasMap: new Map<string, string[]>(),

        setSas(id: string, sas: string[]){
          this.sasMap.set(id, sas);
        },

        getSas(id: string): string[] {
          return this.sasMap.get(id);
        },

        getParticipantsFor(id: string) {
            const list: JitsiParticipant[] = [];
            this.participants.forEach((participant, pId) => {
                if (id !== pId) {
                    list.push(participant);
                }
            });
            return list;
        },

        async enableE2E() {
            for (const [_, keyHandler] of this.listeners) {
                await keyHandler.setEnabled(true);
                expect(keyHandler.isEnabled()).toBe(true);
                expect(keyHandler._olmAdapter.isInitialized()).toBe(true);
            }
        },

        diableE2E() {
            this.listeners.forEach((keyHandler, _id) => {
                keyHandler.setEnabled(false);
            });
        },

        userJoined(keyHandler: ManagedKeyHandler) {
            const pId = keyHandler.conference.myUserId();
            if (!this.listeners.has(pId)) {
                const list: string[] = [];
                this.listeners.forEach((keyHandler, id) => {
                    keyHandler._onParticipantJoined(pId);
                    list.push(id);
                });
                this.listeners.set(pId, keyHandler);

                for (const id of list) {
                    keyHandler._onParticipantJoined(id);
                }

                const participant = createMockParticipant(pId);
                this.participants.set(pId, participant);
            }
        },

        userLeft(pId: string) {
            this.participants.delete(pId);
            this.listeners.forEach((keyHandler, id) => {
                if (id !== pId) {
                    keyHandler._onParticipantLeft(pId);
                }
            });
        },

        sendMessage(myId: string, pId: string, payload: any) {
            this.listeners.forEach((keyHandler, id) => {
                if (id === pId) {
                    keyHandler._onEndpointMessageReceived(
                        this.participants.get(myId),
                        payload,
                    );
                }
            });
        },
    };

    async function createMockManagedKeyHandler(): Promise<{
        id: string;
        keyHandler: ManagedKeyHandler;
    }> {
        const id = new Date().getTime().toString().slice(-8);

        const conferenceMock = mock<JitsiConference>();

        when(conferenceMock.myUserId()).thenReturn(id);

        const mockRTC = new RTC(conferenceMock);
        when(conferenceMock.rtc).thenReturn(mockRTC);

        const eventEmitterMock = mock<EventEmitter>();
        when(eventEmitterMock.emit(anything(), anything())).thenCall( (event, sas) => {
          if (event === JitsiConferenceEvents.E2EE_SAS_AVAILABLE ) {
            xmppServerMock.setSas(id, sas);
          }
        } );

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

        return { id, keyHandler };
    }

    function createMockParticipant(participantId: string): JitsiParticipant {
        const mockParticipant = mock(JitsiParticipant);
        when(mockParticipant.getId()).thenReturn(participantId);
        when(mockParticipant.hasFeature(anything())).thenReturn(true);
        const participant = instance(mockParticipant);
        return participant;
    }

    function verifyRequestRecived(olmAdapterSpy: OlmAdapter, pId: string) {
        verify(olmAdapterSpy.createSessionInitMessage(pId, anything())).never();
        verify(
            olmAdapterSpy.createPQsessionInitMessage(
                pId,
                anything(),
                anything(),
                anything(),
                anything(),
            ),
        ).called();
        verify(
            olmAdapterSpy.createPQsessionAckMessage(
                pId,
                anything(),
                anything(),
                anything(),
                anything(),
            ),
        ).never();
        verify(
            olmAdapterSpy.createSessionAckMessage(
                pId,
                anything(),
                anything(),
                anything(),
            ),
        ).called();
        verify(
            olmAdapterSpy.createSessionDoneMessage(pId, anything(), anything()),
        ).never();
    }

    function verifyRequestSent(olmAdapterSpy: OlmAdapter, pId: string) {
        verify(
            olmAdapterSpy.createSessionInitMessage(pId, anything()),
        ).called();
        verify(
            olmAdapterSpy.createPQsessionInitMessage(
                pId,
                anything(),
                anything(),
                anything(),
                anything(),
            ),
        ).never();
        verify(
            olmAdapterSpy.createPQsessionAckMessage(
                pId,
                anything(),
                anything(),
                anything(),
                anything(),
            ),
        ).called();
        verify(
            olmAdapterSpy.createSessionAckMessage(
                pId,
                anything(),
                anything(),
                anything(),
            ),
        ).never();
        verify(
            olmAdapterSpy.createSessionDoneMessage(pId, anything(), anything()),
        ).called();
    }
    it("should enable e2e sucessfully for 3 participants", async () => {
        const {
            id: idA,
            keyHandler: alice,
        } = await createMockManagedKeyHandler();
        const {
            id: idB,
            keyHandler: bob,
        } = await createMockManagedKeyHandler();
        const {
            id: idE,
            keyHandler: eve,
        } = await createMockManagedKeyHandler();

        const aliceSpy = spy(alice);
        const bobSpy = spy(bob);
        const eveSpy = spy(eve);

        const olmAliceSpy = spy(alice._olmAdapter);
        const olmBobSpy = spy(bob._olmAdapter);
        const olmEveSpy = spy(eve._olmAdapter);

        const e2eeCtxAliceSpy = spy(alice.e2eeCtx);
        const e2eeCtxBobSpy = spy(bob.e2eeCtx);
        const e2eeCtxEveSpy = spy(eve.e2eeCtx);

        xmppServerMock.userJoined(alice);
        xmppServerMock.userJoined(bob);

        verify((aliceSpy as any)._onParticipantJoined(idB)).called();
        verify((bobSpy as any)._onParticipantJoined(idA)).called();

        xmppServerMock.userJoined(eve);

        verify((aliceSpy as any)._onParticipantJoined(idE)).called();
        verify((bobSpy as any)._onParticipantJoined(idE)).called();
        verify((eveSpy as any)._onParticipantJoined(idA)).called();
        verify((eveSpy as any)._onParticipantJoined(idB)).called();

        await xmppServerMock.enableE2E();

        verify(aliceSpy.enableE2E()).called();
        verify(bobSpy.enableE2E()).called();
        verify(eveSpy.enableE2E()).called();

        verify(olmAliceSpy.generateOneTimeKeys(0)).called();
        verify(olmBobSpy.generateOneTimeKeys(1)).called();
        verify(olmEveSpy.generateOneTimeKeys(2)).called();

        verifyRequestRecived(olmAliceSpy, idB);
        verifyRequestRecived(olmAliceSpy, idE);

        verifyRequestRecived(olmBobSpy, idE);
        verifyRequestSent(olmBobSpy, idA);

        verifyRequestSent(olmEveSpy, idA);
        verifyRequestSent(olmEveSpy, idB);

        verify(
            (e2eeCtxAliceSpy as any).setKey(
                idA,
                anything(),
                anything(),
                anything(),
            ),
        ).once();
        verify(
            (e2eeCtxAliceSpy as any).setKey(
                idB,
                anything(),
                anything(),
                anything(),
            ),
        ).once();
        verify(
            (e2eeCtxAliceSpy as any).setKey(
                idE,
                anything(),
                anything(),
                anything(),
            ),
        ).once();
        verify(
            (e2eeCtxBobSpy as any).setKey(
                idA,
                anything(),
                anything(),
                anything(),
            ),
        ).once();
        verify(
            (e2eeCtxBobSpy as any).setKey(
                idB,
                anything(),
                anything(),
                anything(),
            ),
        ).once();
        verify(
            (e2eeCtxBobSpy as any).setKey(
                idE,
                anything(),
                anything(),
                anything(),
            ),
        ).once();
        verify(
            (e2eeCtxEveSpy as any).setKey(
                idA,
                anything(),
                anything(),
                anything(),
            ),
        ).once();
        verify(
            (e2eeCtxEveSpy as any).setKey(
                idB,
                anything(),
                anything(),
                anything(),
            ),
        ).once();
        verify(
            (e2eeCtxEveSpy as any).setKey(
                idE,
                anything(),
                anything(),
                anything(),
            ),
        ).once();

        await delay(800);

        console.log("Alice SAS values", xmppServerMock.getSas(idA));
        console.log("Bob SAS values", xmppServerMock.getSas(idB));
        console.log("Eve SAS values", xmppServerMock.getSas(idE));
    });
});
