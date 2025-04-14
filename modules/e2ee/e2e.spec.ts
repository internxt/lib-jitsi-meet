import { ManagedKeyHandler } from '../../modules/e2ee/ManagedKeyHandler';
import JitsiConference from '../../JitsiConference';
import JitsiParticipant from '../../JitsiParticipant';

import { mock, instance, when, anything, verify, spy } from 'ts-mockito';
import initKyber from '@dashlane/pqc-kem-kyber512-browser/dist/pqc-kem-kyber512.js';
import initOlm from 'vodozemac-wasm/javascript/pkg/vodozemac.js';
import RTC from '../RTC/RTC';

function delay(ms: number) {
  return new Promise( resolve => setTimeout(resolve, ms) );
}

describe('Test e2e module', () => {

    beforeAll(async () => {
        const kyberPath = '/base/node_modules/@dashlane/pqc-kem-kyber512-browser/dist/pqc-kem-kyber512.wasm';
        await initKyber(kyberPath);
        const wasmPath = '/base/node_modules/vodozemac-wasm/javascript/pkg/vodozemac_bg.wasm';
        await initOlm(wasmPath);
      });

    const xmppServerMock = {
      listeners: new Map<string, ManagedKeyHandler>(),
      participants: new Map<string, JitsiParticipant>(),

      getParticipantsFor(id: string) {
        const list: JitsiParticipant[] = [];
        this.participants.forEach((participant, pId) => {
           if(id !== pId){
            list.push(participant);
           }
        });
        return list;
      },

      async enableE2E(){
        for (const [_, keyHandler] of this.listeners) {
          await keyHandler.setEnabled(true);
        }
      },

      diableE2E(){
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

      userLeft(pId: string){
        this.participants.delete(pId);
        this.listeners.forEach((keyHandler, id) => {
          if (id !== pId) {
            keyHandler._onParticipantLeft(pId);
          }
        });
      },
      
    
      
      sendMessage(pId: string, payload: any) {
        this.listeners.forEach((keyHandler, id) => {
          if (id === pId) {
           keyHandler._onEndpointMessageReceived(this.participants.get(pId), payload);
          }
        });
      }
    };

    async function createMockManagedKeyHandler(): Promise<{id: string, keyHandler: ManagedKeyHandler}> {
      const id = new Date().getTime().toString().slice(-8);

      const conferenceMock = mock<JitsiConference>();

      when(conferenceMock.myUserId()).thenReturn(id);
      
      const mockRTC = new RTC(conferenceMock);
      when(conferenceMock.rtc).thenReturn(mockRTC);

      const eventHandlers = new Map<string, Function[]>();
      when(conferenceMock.on(anything(), anything())).thenCall((eventName, handler) => {
        if (!eventHandlers.has(eventName)) {
          eventHandlers.set(eventName, []);
        }
        eventHandlers.get(eventName)?.push(handler);
        return conferenceMock;
      });
      when(conferenceMock.getParticipants()).thenCall( () => {
        return xmppServerMock.getParticipantsFor(id);
      }
      );

      when(conferenceMock.sendMessage(anything(), anything())).thenCall((pId, payload) => {
        xmppServerMock.sendMessage(pId, payload);
      });

        const conference = instance(conferenceMock);
        const keyHandler = new ManagedKeyHandler(conference);
        await delay(100);
        
        return {id, keyHandler};
      }


    function createMockParticipant(participantId: string): JitsiParticipant {
        const mockParticipant = mock(JitsiParticipant);
        when(mockParticipant.getId()).thenReturn(participantId);
        when(mockParticipant.hasFeature(anything())).thenReturn(true);
        const participant = instance(mockParticipant);
        return participant;
      }
    
    it('should enable e2e sucessfully', async () => {

        const {id: idA, keyHandler: alice } = await createMockManagedKeyHandler();
        const {id: idB, keyHandler: bob } = await createMockManagedKeyHandler();
        const {id: idE, keyHandler: eve } = await createMockManagedKeyHandler();

        console.log('IDs we have', idA, idB, idE);

        const aliceSpy = spy(alice);
        const bobSpy = spy(bob);
        const eveSpy = spy(eve);

        const olmAliceSpy = spy(alice._olmAdapter);
        const olmBobSpy = spy(bob._olmAdapter);
        const olmEveSpy = spy(eve._olmAdapter);

 
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

        expect(alice.isEnabled()).toBe(true);
        expect(bob.isEnabled()).toBe(true);
        expect(eve.isEnabled()).toBe(true);

        expect(alice._olmAdapter.isInitialized()).toBe(true);
        expect(bob._olmAdapter.isInitialized()).toBe(true);
        expect(eve._olmAdapter.isInitialized()).toBe(true);

        verify(aliceSpy.enableE2E()).called();
        verify(bobSpy.enableE2E()).called();
        verify(eveSpy.enableE2E()).called();

        

        verify(olmAliceSpy.generateOneTimeKeys(0)).called();
        verify(olmBobSpy.generateOneTimeKeys(1)).called();
        verify(olmEveSpy.generateOneTimeKeys(2)).called();
       

        verify(olmAliceSpy.createSessionInitMessage(anything(),anything())).never();
        verify(olmBobSpy.createSessionInitMessage(idA,anything())).called();
        verify(olmEveSpy.createSessionInitMessage(idA,anything())).called();
        verify(olmEveSpy.createSessionInitMessage(idB,anything())).called(); 

    });
    
});