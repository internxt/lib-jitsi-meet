import { anything, verify, spy } from "ts-mockito";

import { OlmAdapter } from "../modules/e2ee/OlmAdapter.ts";
import E2EEContext from "../modules/e2ee/E2EEContext.ts";

import {
    WorkerMock,
    XmppServerMock,
    createMockManagedKeyHandler,
    delay,
} from "./mocks.ts";

import initKyber from "@dashlane/pqc-kem-kyber512-browser/dist/pqc-kem-kyber512.js";
import initOlm from "vodozemac-wasm/javascript/pkg/vodozemac.js";

describe("Test E2E:", () => {
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

    it("should sucessfully enable e2e for 3 participants", async () => {
        const xmppServerMock = new XmppServerMock();

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

        await delay(800);

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

    it("two participants should sucessfully join an ongoing e2e meeting", async () => {
        const xmppServerMock = new XmppServerMock();

        const { id: idA, keyHandler: alice } =
            await createMockManagedKeyHandler(xmppServerMock);
        const { id: idB, keyHandler: bob } =
            await createMockManagedKeyHandler(xmppServerMock);
        const { id: idE, keyHandler: eve } =
            await createMockManagedKeyHandler(xmppServerMock);

        const olmAliceSpy = spy(alice._olmAdapter);
        const olmBobSpy = spy(bob._olmAdapter);
        const olmEveSpy = spy(eve._olmAdapter);

        const e2eeCtxAliceSpy = spy(alice.e2eeCtx);
        const e2eeCtxBobSpy = spy(bob.e2eeCtx);
        const e2eeCtxEveSpy = spy(eve.e2eeCtx);

        xmppServerMock.userJoined(alice);
        xmppServerMock.userJoined(bob);
        xmppServerMock.userJoined(eve);

        await xmppServerMock.enableE2E();

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

        const { id: idM, keyHandler: mallory } =
            await createMockManagedKeyHandler(xmppServerMock);
        const { id: idJ, keyHandler: john } =
            await createMockManagedKeyHandler(xmppServerMock);

        const e2eeCtxJohnSpy = spy(john.e2eeCtx);
        const olmMallorySpy = spy(mallory._olmAdapter);
        const olmJohnSpy = spy(john._olmAdapter);

        xmppServerMock.userJoined(mallory);
        await delay(30);
        xmppServerMock.userJoined(john);

        await delay(3000);

        verify(olmAliceSpy.ratchetMyKeys()).times(2);
        verify(olmBobSpy.ratchetMyKeys()).times(2);
        verify(olmEveSpy.ratchetMyKeys()).times(2);
        verify(olmMallorySpy.ratchetMyKeys()).once();
        verify(olmJohnSpy.ratchetMyKeys()).never();

        verify(e2eeCtxAliceSpy.ratchetKeys(idB)).times(2);
        verify(e2eeCtxAliceSpy.ratchetKeys(idE)).times(2);
        verify(e2eeCtxBobSpy.ratchetKeys(idA)).times(2);
        verify(e2eeCtxBobSpy.ratchetKeys(idE)).times(2);
        verify(e2eeCtxEveSpy.ratchetKeys(idA)).times(2);
        verify(e2eeCtxEveSpy.ratchetKeys(idB)).times(2);

        verify(
            (e2eeCtxJohnSpy as any).setKey(
                idA,
                anything(),
                anything(),
                anything(),
            ),
        ).once();
        verify(
            (e2eeCtxJohnSpy as any).setKey(
                idB,
                anything(),
                anything(),
                anything(),
            ),
        ).once();
        verify(
            (e2eeCtxJohnSpy as any).setKey(
                idE,
                anything(),
                anything(),
                anything(),
            ),
        ).once();
        verify(
            (e2eeCtxJohnSpy as any).setKey(
                idM,
                anything(),
                anything(),
                anything(),
            ),
        ).once();
        verify(
            (e2eeCtxJohnSpy as any).setKey(
                idJ,
                anything(),
                anything(),
                anything(),
            ),
        ).once();

        const sasA_new = xmppServerMock.getSas(idA);
        const sasB_new = xmppServerMock.getSas(idB);
        const sasE_new = xmppServerMock.getSas(idE);
        const sasM = xmppServerMock.getSas(idM);
        const sasJ = xmppServerMock.getSas(idJ);

        console.log("New Alice SAS values", sasA_new);
        console.log("New Bob SAS values", sasB_new);
        console.log("New Eve SAS values", sasE_new);
        console.log("Mallory SAS values", sasM);
        console.log("John SAS values", sasJ);

        expect(sasA_new.length).toBe(7);
        expect(sasA_new).toEqual(sasB_new);
        expect(sasA_new).toEqual(sasE_new);
        expect(sasA_new).toEqual(sasM);
        expect(sasA_new).toEqual(sasJ);
    });

    it("two participants should sucessfully leave an ongoing e2e meeting", async () => {
        const xmppServerMock = new XmppServerMock();

        const { id: idA, keyHandler: alice } =
            await createMockManagedKeyHandler(xmppServerMock);
        const { id: idB, keyHandler: bob } =
            await createMockManagedKeyHandler(xmppServerMock);
        const { id: idE, keyHandler: eve } =
            await createMockManagedKeyHandler(xmppServerMock);
        const { id: idM, keyHandler: mallory } =
            await createMockManagedKeyHandler(xmppServerMock);
        const { id: idJ, keyHandler: john } =
            await createMockManagedKeyHandler(xmppServerMock);

        const olmAliceSpy = spy(alice._olmAdapter);
        const olmBobSpy = spy(bob._olmAdapter);
        const olmEveSpy = spy(eve._olmAdapter);

        xmppServerMock.userJoined(alice);
        xmppServerMock.userJoined(bob);
        xmppServerMock.userJoined(eve);
        xmppServerMock.userJoined(mallory);
        xmppServerMock.userJoined(john);

        await xmppServerMock.enableE2E();

        await delay(800);

        const sasA = xmppServerMock.getSas(idA);
        const sasB = xmppServerMock.getSas(idB);
        const sasE = xmppServerMock.getSas(idE);
        const sasM = xmppServerMock.getSas(idM);
        const sasJ = xmppServerMock.getSas(idJ);

        console.log("Alice SAS values", sasA);
        console.log("Bob SAS values", sasB);
        console.log("Eve SAS values", sasE);
        console.log("Mallory SAS values", sasM);
        console.log("John SAS values", sasJ);

        expect(sasA.length).toBe(7);
        expect(sasA).toEqual(sasB);
        expect(sasA).toEqual(sasE);
        expect(sasA).toEqual(sasM);
        expect(sasA).toEqual(sasJ);

        xmppServerMock.userLeft(idM);
        xmppServerMock.userLeft(idJ);

        await delay(800);

        verify(olmAliceSpy.updateMyKeys()).times(3);
        verify(olmBobSpy.updateMyKeys()).times(3);
        verify(olmEveSpy.updateMyKeys()).times(3);

        const newSasA = xmppServerMock.getSas(idA);
        const newSasB = xmppServerMock.getSas(idB);
        const newSasE = xmppServerMock.getSas(idE);

        console.log("New Alice SAS values", newSasA);
        console.log("New Bob SAS values", newSasB);
        console.log("New Eve SAS values", newSasE);

        expect(newSasA.length).toBe(7);
        expect(newSasA).toEqual(newSasB);
        expect(newSasA).toEqual(newSasE);
    });
});
