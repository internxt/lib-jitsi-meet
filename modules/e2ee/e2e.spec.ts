import { ManagedKeyHandler } from '../../modules/e2ee/ManagedKeyHandler';
import JitsiConference from '../../JitsiConference';
import JitsiParticipant from '../../JitsiParticipant';
import EventEmitter from '../util/EventEmitter';

import { mock, instance, when, anything, verify } from 'ts-mockito';
import initKyber from '@dashlane/pqc-kem-kyber512-browser/dist/pqc-kem-kyber512.js';
import initOlm from 'vodozemac-wasm/javascript/pkg/vodozemac.js';


describe('Test e2e module', () => {

    let allParticipants: Record<string, JitsiParticipant> = {};

    beforeAll(async () => {
        const kyberPath = '/base/node_modules/@dashlane/pqc-kem-kyber512-browser/dist/pqc-kem-kyber512.wasm';
        await initKyber(kyberPath);
        const wasmPath = '/base/node_modules/vodozemac-wasm/javascript/pkg/vodozemac_bg.wasm';
        await initOlm(wasmPath);
      });

    beforeEach( () => {
        allParticipants = {};
    });

    function createMockConference(id: string): JitsiConference {
        const realEventEmitter = new EventEmitter();
        const mockConference = mock(JitsiConference);
        when(mockConference.eventEmitter).thenReturn(realEventEmitter);
        when(mockConference.myUserId()).thenReturn(id);
        when(mockConference.getParticipants()).thenReturn(Object.values(allParticipants));
        when(mockConference.on(anything(), anything())).thenCall((eventName, listener) => {
            realEventEmitter.on(eventName, listener);
        });
        when(mockConference.emit(anything(), anything())).thenCall((eventName, ...args) => {
            realEventEmitter.emit(eventName, ...args);
        });
        const rtcStub = { on: () => {} }; 
        when(mockConference.rtc).thenReturn(rtcStub);

        return instance(mockConference);
      }

    function createMockParticipant(participantId: string): JitsiParticipant {
        const mockParticipant = mock(JitsiParticipant);
        when(mockParticipant.getId()).thenReturn(participantId);
        when(mockParticipant.hasFeature(anything())).thenReturn(true);
        return mockParticipant;
      }

    function createMockManagedKeyHandler(): { id: string, keyHandler: ManagedKeyHandler } {

        const id = new Date().getTime().toString().slice(-8);
        const keyHandlerMock = mock(ManagedKeyHandler);
        const mockedConference = createMockConference(id);

        const realKeyHandler = new ManagedKeyHandler(mockedConference);
        when(keyHandlerMock.conference).thenReturn(mockedConference);
        when(keyHandlerMock.setEnabled(anything())).thenCall(
            (...args) => realKeyHandler.setEnabled(args[0])
          );
        when(keyHandlerMock.isEnabled()).thenCall(
            () => realKeyHandler.isEnabled()
          );
        when(keyHandlerMock.setKey(anything(), anything(), anything())).thenCall(
            (...args) => realKeyHandler.setKey(args[0], args[1], args[2])
          );
        when(keyHandlerMock._onParticipantJoined(anything())).thenCall(
            (...args) => realKeyHandler._onParticipantJoined(args[0])
        );
        when(keyHandlerMock._onParticipantLeft(anything(), anything())).thenCall(
            (...args) => realKeyHandler._onParticipantLeft(args[0], args[1])
        );
              

        const keyHandler = instance(keyHandlerMock);

        const participant =  createMockParticipant(id);
        allParticipants[id] = participant;

        console.log(`ID TESTING: ${keyHandler.conference.myUserId()}`); 

        return {id, keyHandler };
    }

    
    it('should enable e2e sucessfully', async () => {

        const { id: idAlice, keyHandler: Alice } = createMockManagedKeyHandler();
        const { id: idBob, keyHandler: Bob } = createMockManagedKeyHandler();
        const { id: idEve, keyHandler: Eve } = createMockManagedKeyHandler();

        verify(Alice._onParticipantJoined(idBob));
        verify(Alice._onParticipantJoined(idEve));

        verify(Bob._onParticipantJoined(idAlice));
        verify(Bob._onParticipantJoined(idEve));

        verify(Eve._onParticipantJoined(idAlice));
        verify(Eve._onParticipantJoined(idBob));

        Alice.setEnabled(true);
        Bob.setEnabled(true);
        Eve.setEnabled(true);

        expect(Alice.isEnabled()).toBe(true);
        expect(Bob.isEnabled()).toBe(true);
        expect(Eve.isEnabled()).toBe(true);
       
    });
    
});