import { anything, verify, spy } from "ts-mockito";

import { OlmAdapter } from "../modules/e2ee/OlmAdapter.ts";
import E2EEContext from "../modules/e2ee/E2EEContext.ts";

import {WorkerMock, XmppServerMock, createMockManagedKeyHandler, delay} from "./mocks.ts";

import initKyber from "@dashlane/pqc-kem-kyber512-browser/dist/pqc-kem-kyber512.js";
import initOlm from "vodozemac-wasm/javascript/pkg/vodozemac.js";


describe("E2EEcontext with multiple instances", () => {

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

    it("should create separate workers for each E2EEcontext instance", async () => {
        const context1 = new E2EEContext();
        const context2 = new E2EEContext();

        const contextSpy1 = spy(context1);
        const contextSpy2 = spy(context2);

        const key1 = crypto.getRandomValues(new Uint8Array(32));
        const key2 = crypto.getRandomValues(new Uint8Array(32));

        context1.setKey("participant1", key1, key1, 1);
        context2.setKey("participant2", key2, key2, 1);

        await delay(800);

        verify((contextSpy1 as any).updateSAS(anything())).called();
        verify((contextSpy2 as any).updateSAS(anything())).called();
    });

    
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

        const xmppServerMock  = new XmppServerMock();

        const { id: idA, keyHandler: alice } =
            await createMockManagedKeyHandler(xmppServerMock);
        const { id: idB, keyHandler: bob } =
            await createMockManagedKeyHandler(xmppServerMock);
        const { id: idE, keyHandler: eve } =
            await createMockManagedKeyHandler(xmppServerMock);

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

        const sasA = xmppServerMock.getSas(idA);
        const sasB = xmppServerMock.getSas(idB);
        const sasE = xmppServerMock.getSas(idE);

        console.log("Alice SAS values", sasA);
        console.log("Bob SAS values", sasB);
        console.log("Eve SAS values", sasE);

        expect(sasA.length).toBe(7);
        expect(sasA).toEqual(sasB);
        expect(sasA).toEqual(sasE);
    });
});
