import { anything, verify, spy } from "ts-mockito";

import { OlmAdapter } from "../modules/e2ee/OlmAdapter.ts";
import E2EEContext from "../modules/e2ee/E2EEContext.ts";
import { ManagedKeyHandler } from "../modules/e2ee/ManagedKeyHandler";

import {
    WorkerMock,
    XmppServerMock,
    createMockManagedKeyHandler,
    delay,
} from "./mocks.ts";

import initKyber from "@dashlane/pqc-kem-kyber512-browser/dist/pqc-kem-kyber512.js";
import initOlm from "vodozemac-wasm/javascript/pkg/vodozemac.js";

type UserData = {
    index: number;
    id: string;
    keyHandlerSpy: ManagedKeyHandler;
    olmSpy: OlmAdapter;
    e2eeSpy: E2EEContext;
};

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

    function verifyParticipantNumber(
        xmppServerMock: XmppServerMock,
        expected: number,
    ) {
        const userIds = xmppServerMock.getAllParticipantsIDs();
        expect(userIds.length).toBe(expected);
    }

    function verifySasValues(xmppServerMock: XmppServerMock) {
        const userIds = xmppServerMock.getAllParticipantsIDs();
        const sasValues = userIds.map((id) => xmppServerMock.getSas(id));

        userIds.forEach((id, index) => {
            console.log(`SAS values of ${id} is:`, sasValues[index]);
        });

        sasValues.forEach((sas) => {
            expect(sas.length).toBe(7);
            expect(sas).toEqual(sasValues[0]);
        });
    }

    async function createGroupMeeting(
        xmppServerMock: XmppServerMock,
        participantCount: number,
    ) {
        const userData: UserData[] = [];

        for (let i = 0; i < participantCount; i++) {
            const { id, keyHandler } =
                await createMockManagedKeyHandler(xmppServerMock);

            const olmSpy = spy(keyHandler._olmAdapter);
            const e2eeSpy = spy(keyHandler.e2eeCtx);
            const keyHandlerSpy = spy(keyHandler);

            xmppServerMock.userJoined(keyHandler);

            userData.push({
                index: i,
                id,
                keyHandlerSpy,
                olmSpy,
                e2eeSpy,
            });
        }
        return userData;
    }

    function verifyAllChannels(userData: UserData[], times: number = 1) {
        const n = userData.length;
        for (let i = 0; i < n; i++) {
            const user = userData[i];
            const olmSpy = user.olmSpy;

            verify(olmSpy.generateOneTimeKeys(user.index)).called();
            verify(user.keyHandlerSpy.enableE2E()).called();

            for (let j = 0; j < n; j++) {
                const pID = userData[j].id;
                verify(
                    (user.e2eeSpy as any).setKey(
                        pID,
                        anything(),
                        anything(),
                        anything(),
                    ),
                ).times(times);

                if (i > j) {
                    verifyRequestSent(olmSpy, pID);
                } else if (i < j) {
                    verifyRequestRecived(olmSpy, pID);
                }
            }
        }
    }

    it("should sucessfully enable e2e for a group meeting", async () => {
        const participantCount = 3;
        expect(participantCount).toBeGreaterThan(0);

        const xmppServerMock = new XmppServerMock();
        const userData = await createGroupMeeting(
            xmppServerMock,
            participantCount,
        );
        expect(userData.length).toBe(participantCount);

        await xmppServerMock.enableE2E();

        await delay(800);

        verifyAllChannels(userData);
        verifyParticipantNumber(xmppServerMock, participantCount);
        verifySasValues(xmppServerMock);
    });

    it("participants should sucessfully join an ongoing e2e meeting", async () => {
        const initialParticipantCount = 3;
        const joinedParticipantsNumber = 2;
        expect(initialParticipantCount).toBeGreaterThan(0);
        expect(joinedParticipantsNumber).toBeGreaterThan(0);

        const xmppServerMock = new XmppServerMock();
        const userData = await createGroupMeeting(
            xmppServerMock,
            initialParticipantCount,
        );
        expect(userData.length).toBe(initialParticipantCount);

        await xmppServerMock.enableE2E();

        await delay(800);

        verifyParticipantNumber(xmppServerMock, initialParticipantCount);
        verifySasValues(xmppServerMock);

        const joinedUserData: UserData[] = [];
        for (let i = 1; i <= joinedParticipantsNumber; i++) {
            const { id, keyHandler } =
                await createMockManagedKeyHandler(xmppServerMock);
            const olmSpy = spy(keyHandler._olmAdapter);
            const e2eeSpy = spy(keyHandler.e2eeCtx);
            const keyHandlerSpy = spy(keyHandler);
            joinedUserData.push({
                index: i,
                id,
                keyHandlerSpy,
                olmSpy,
                e2eeSpy,
            });

            xmppServerMock.userJoined(keyHandler);
        }
        expect(joinedUserData.length).toBe(joinedParticipantsNumber);

        await delay(800);

        userData.forEach((user) => {
            verify(user.olmSpy.ratchetMyKeys()).times(joinedParticipantsNumber);
            for (let j = 0; j < initialParticipantCount; j++) {
                if (j !== user.index) {
                    const pID = userData[j].id;
                    verify(user.e2eeSpy.ratchetKeys(pID)).times(
                        joinedParticipantsNumber,
                    );
                }
            }
        });

        const userIds = xmppServerMock.getAllParticipantsIDs();
        joinedUserData.forEach((user) => {
            verify(user.olmSpy.ratchetMyKeys()).times(
                joinedParticipantsNumber - user.index,
            );
            userIds.forEach((id) => {
                verify(
                    (user.e2eeSpy as any).setKey(
                        id,
                        anything(),
                        anything(),
                        anything(),
                    ),
                ).called();
            });
        });

        verifyParticipantNumber(
            xmppServerMock,
            initialParticipantCount + joinedParticipantsNumber,
        );
        verifySasValues(xmppServerMock);
    });

    it("participants should sucessfully leave an ongoing e2e meeting", async () => {
        const initialParticipantCount = 5;
        const leftParticipantsNumber = 2;
        expect(initialParticipantCount).toBeGreaterThan(0);
        expect(initialParticipantCount).toBeGreaterThan(leftParticipantsNumber);

        const xmppServerMock = new XmppServerMock();
        const userData = await createGroupMeeting(
            xmppServerMock,
            initialParticipantCount,
        );
        expect(userData.length).toBe(initialParticipantCount);

        await xmppServerMock.enableE2E();

        await delay(800);

        verifyParticipantNumber(xmppServerMock, initialParticipantCount);
        verifySasValues(xmppServerMock);

        const userIds = xmppServerMock.getAllParticipantsIDs();
        for (let i = 0; i < leftParticipantsNumber; i++) {
            const id = userIds[i];
            xmppServerMock.userLeft(id);
            userData.shift();
        }

        await delay(800);

        const remainingParticipantsCount =
            initialParticipantCount - leftParticipantsNumber;

        userData.forEach((user) => {
            verify(user.olmSpy.updateMyKeys()).times(
                1 + leftParticipantsNumber,
            );
        });

        verifyParticipantNumber(xmppServerMock, remainingParticipantsCount);
        verifySasValues(xmppServerMock);
    });

    it("participants should sucessfully join and leave an ongoing e2e meeting", async () => {
        const initialParticipantCount = 1;
        const joinedParticipantsNumber = 4;
        const leftParticipantsNumber = 2;
        expect(initialParticipantCount).toBeGreaterThan(0);
        expect(joinedParticipantsNumber).toBeGreaterThan(0);
        expect(
            initialParticipantCount + joinedParticipantsNumber,
        ).toBeGreaterThan(leftParticipantsNumber);

        const xmppServerMock = new XmppServerMock();
        const userData = await createGroupMeeting(
            xmppServerMock,
            initialParticipantCount,
        );
        expect(userData.length).toBe(initialParticipantCount);

        await xmppServerMock.enableE2E();

        await delay(800);

        verifyParticipantNumber(xmppServerMock, initialParticipantCount);
        verifySasValues(xmppServerMock);

        for (let i = 0; i < joinedParticipantsNumber; i++) {
            const { id, keyHandler } =
                await createMockManagedKeyHandler(xmppServerMock);
            const olmSpy = spy(keyHandler._olmAdapter);
            const e2eeSpy = spy(keyHandler.e2eeCtx);
            const keyHandlerSpy = spy(keyHandler);
            userData.push({
                index: initialParticipantCount + i,
                id,
                keyHandlerSpy,
                olmSpy,
                e2eeSpy,
            });

            xmppServerMock.userJoined(keyHandler);
            await delay(30);
        }
        expect(userData.length).toBe(
            initialParticipantCount + joinedParticipantsNumber,
        );

        const userIds = xmppServerMock.getAllParticipantsIDs();
        for (let i = 0; i < leftParticipantsNumber; i++) {
            const id = userIds[i];
            xmppServerMock.userLeft(id);
            userData.shift();
        }
        const remainingParticipantsCount =
            initialParticipantCount +
            joinedParticipantsNumber -
            leftParticipantsNumber;
        expect(userData.length).toBe(remainingParticipantsCount);

        await delay(800);

        userData.forEach((user) => {
            const x =
                joinedParticipantsNumber +
                initialParticipantCount -
                1 -
                user.index;
            const times =
                x > joinedParticipantsNumber ? joinedParticipantsNumber : x;
            verify(user.olmSpy.ratchetMyKeys()).times(times);

            verify(user.olmSpy.updateMyKeys()).times(
                1 + leftParticipantsNumber,
            );
        });

        verifyParticipantNumber(xmppServerMock, remainingParticipantsCount);
        verifySasValues(xmppServerMock);
    });

    it("participants should sucessfully leave and join an ongoing e2e meeting", async () => {
        const initialParticipantCount = 4;
        const joinedParticipantsNumber = 4;
        const leftParticipantsNumber = 2;
        expect(initialParticipantCount).toBeGreaterThan(0);
        expect(joinedParticipantsNumber).toBeGreaterThan(0);
        expect(initialParticipantCount).toBeGreaterThanOrEqual(
            leftParticipantsNumber,
        );

        const xmppServerMock = new XmppServerMock();
        const userData = await createGroupMeeting(
            xmppServerMock,
            initialParticipantCount,
        );
        expect(userData.length).toBe(initialParticipantCount);

        await xmppServerMock.enableE2E();

        await delay(800);

        verifyParticipantNumber(xmppServerMock, initialParticipantCount);
        verifySasValues(xmppServerMock);

        const userIds = xmppServerMock.getAllParticipantsIDs();
        for (let i = 0; i < leftParticipantsNumber; i++) {
            const id = userIds[i];
            xmppServerMock.userLeft(id);
            userData.shift();
        }

        expect(userData.length).toBe(
            initialParticipantCount - leftParticipantsNumber,
        );

        for (let i = 0; i < joinedParticipantsNumber; i++) {
            const { id, keyHandler } =
                await createMockManagedKeyHandler(xmppServerMock);
            const olmSpy = spy(keyHandler._olmAdapter);
            const e2eeSpy = spy(keyHandler.e2eeCtx);
            const keyHandlerSpy = spy(keyHandler);
            userData.push({
                index: initialParticipantCount + i,
                id,
                keyHandlerSpy,
                olmSpy,
                e2eeSpy,
            });

            xmppServerMock.userJoined(keyHandler);
            await delay(30);
        }

        const remainingParticipantsCount =
            initialParticipantCount -
            leftParticipantsNumber +
            joinedParticipantsNumber;
        expect(userData.length).toBe(remainingParticipantsCount);

        await delay(800);

        let times = joinedParticipantsNumber;
        userData.forEach((user) => {
            if (user.index < initialParticipantCount) {
                verify(user.olmSpy.ratchetMyKeys()).times(times);
                verify(user.olmSpy.updateMyKeys()).times(
                    1 + leftParticipantsNumber,
                );
            } else {
                times--;
                verify(user.olmSpy.ratchetMyKeys()).times(times);
                verify(user.olmSpy.updateMyKeys()).once();
            }
        });

        verifyParticipantNumber(xmppServerMock, remainingParticipantsCount);
        verifySasValues(xmppServerMock);
    });

    it("should sucessfully enable, diable and enable again e2e for a group meeting", async () => {
        const participantCount = 3;
        expect(participantCount).toBeGreaterThan(0);

        const xmppServerMock = new XmppServerMock();
        const userData = await createGroupMeeting(
            xmppServerMock,
            participantCount,
        );
        expect(userData.length).toBe(participantCount);

        await xmppServerMock.enableE2E();

        await delay(800);

        verifyAllChannels(userData);
        verifyParticipantNumber(xmppServerMock, participantCount);
        verifySasValues(xmppServerMock);

        await xmppServerMock.diableE2E();

        await delay(800);

        await xmppServerMock.enableE2E();

        await delay(800);

        verifyAllChannels(userData, 2);
        verifyParticipantNumber(xmppServerMock, participantCount);
        verifySasValues(xmppServerMock);
    });
});
