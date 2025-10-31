import { anything, verify, spy } from "ts-mockito";

import { OlmAdapter } from "../modules/e2ee-internxt/OlmAdapter";
import E2EEContext from "../modules/e2ee-internxt/E2EEContext";
import { ManagedKeyHandler } from "../modules/e2ee-internxt/ManagedKeyHandler";

import {
    WorkerMock,
    XmppServerMock,
    createInitializedManagedKeyHandler,
    delay,
} from "./mocks.ts";

import initOlm from "vodozemac-wasm/javascript/pkg/vodozemac.js";

const TEST_TIMEOUT = 1000;
const WAIT_TO_AVOID_SAME_ID = 1;
const WAIT_FOR_CHANNELS = 2 * TEST_TIMEOUT;
const MAX_TEST_TIME = 10 * WAIT_FOR_CHANNELS;

type UserData = {
    index: number;
    id: string;
    keyHandlerSpy: ManagedKeyHandler;
    olmSpy: OlmAdapter;
    e2eeSpy: E2EEContext;
};

describe("Test E2E:", () => {
    beforeEach(async () => {
        const wasmPath =
            "/base/node_modules/vodozemac-wasm/javascript/pkg/vodozemac_bg.wasm";
        await initOlm(wasmPath);
        (window as any).Worker = WorkerMock;
    });

    it(
        "should create separate workers for each E2EEcontext instance",
        async () => {
            const context1 = new E2EEContext();
            const context2 = new E2EEContext();
            context1.setKeysCommitment("participant1", "key commitment 1");
            context2.setKeysCommitment("participant2", "key commitment 2");

            const contextSpy1 = spy(context1);
            const contextSpy2 = spy(context2);

            const key1 = crypto.getRandomValues(new Uint8Array(32));
            const key2 = crypto.getRandomValues(new Uint8Array(32));

            context1.setKey("participant1", key1, key1, 1);
            context2.setKey("participant2", key2, key2, 1);

            await delay(WAIT_FOR_CHANNELS);

            verify((contextSpy1 as any).updateSAS(anything())).called();
            verify((contextSpy2 as any).updateSAS(anything())).called();
        },
        MAX_TEST_TIME,
    );

    /**
     * Verifies that participant recived and processed e2e channel establishement request
     *
     */
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

    /**
     * Verifies that participant sent and processed e2e channel establishement request
     *
     */
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

    /**
     * Verifies that all participants have the same SAS value
     *
     */
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

    /**
     * Creates a new group meeting and xmpp server
     *
     */
    async function createGroupMeeting(participantCount: number) {
        const xmppServerMock = new XmppServerMock();
        const userData: UserData[] = [];

        for (let i = 0; i < participantCount; i++) {
            const { id, keyHandler } = await createInitializedManagedKeyHandler(
                xmppServerMock,
                TEST_TIMEOUT,
            );
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
            await delay(WAIT_TO_AVOID_SAME_ID);
        }
        return { xmppServerMock, userData };
    }

    /**
     * Verifies that all participants established e2e channels between each other and got keys
     *
     */
    function verifyAllChannels(userData: UserData[], index: number = 0) {
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
                        index,
                    ),
                ).once();

                if (i > j) {
                    verifyRequestSent(olmSpy, pID);
                } else if (i < j) {
                    verifyRequestRecived(olmSpy, pID);
                }
            }
        }
    }

    it(
        "should sucessfully enable e2e for a group meeting",
        async () => {
            const participantCount = 3;
            expect(participantCount).toBeGreaterThan(0);

            const { xmppServerMock, userData } =
                await createGroupMeeting(participantCount);
            expect(userData.length).toBe(participantCount);

            xmppServerMock.enableE2E();

            await delay(WAIT_FOR_CHANNELS);

            verifyAllChannels(userData);
            verifyParticipantNumber(xmppServerMock, participantCount);
            verifySasValues(xmppServerMock);
        },
        MAX_TEST_TIME,
    );

    it(
        "participants should sucessfully join an ongoing e2e meeting",
        async () => {
            const initialParticipantCount = 3;
            const joinedParticipantsNumber = 2;
            expect(initialParticipantCount).toBeGreaterThan(0);
            expect(joinedParticipantsNumber).toBeGreaterThan(0);

            const { xmppServerMock, userData } = await createGroupMeeting(
                initialParticipantCount,
            );
            expect(userData.length).toBe(initialParticipantCount);

            xmppServerMock.enableE2E();

            await delay(WAIT_FOR_CHANNELS);

            verifyParticipantNumber(xmppServerMock, initialParticipantCount);
            verifySasValues(xmppServerMock);
            for (let i = 0; i < joinedParticipantsNumber; i++) {
                const { id, keyHandler } =
                    await createInitializedManagedKeyHandler(
                        xmppServerMock,
                        TEST_TIMEOUT,
                    );
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
            }
            expect(userData.length).toBe(
                initialParticipantCount + joinedParticipantsNumber,
            );

            await delay(WAIT_FOR_CHANNELS);

            // original meeting participants should ratchet their key every joinedParticipantsNumber times
            // others as many times as number of user joined after them
            userData.forEach((user) => {
                const x =
                    joinedParticipantsNumber +
                    initialParticipantCount -
                    1 -
                    user.index;
                const times =
                    x > joinedParticipantsNumber ? joinedParticipantsNumber : x;
                verify(user.olmSpy.ratchetMyKeys()).times(times);
            });

            //all participants should set keys for all other participants
            const userIds = xmppServerMock.getAllParticipantsIDs();
            userData.forEach((user) => {
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
        },
        MAX_TEST_TIME,
    );

    it(
        "participants should sucessfully leave an ongoing e2e meeting",
        async () => {
            const initialParticipantCount = 5;
            const leftParticipantsNumber = 2;
            expect(initialParticipantCount).toBeGreaterThan(0);
            expect(initialParticipantCount).toBeGreaterThan(
                leftParticipantsNumber,
            );

            const { xmppServerMock, userData } = await createGroupMeeting(
                initialParticipantCount,
            );
            expect(userData.length).toBe(initialParticipantCount);

            xmppServerMock.enableE2E();

            await delay(WAIT_FOR_CHANNELS);

            verifyParticipantNumber(xmppServerMock, initialParticipantCount);
            verifySasValues(xmppServerMock);

            const userIds = xmppServerMock.getAllParticipantsIDs();
            for (let i = 0; i < leftParticipantsNumber; i++) {
                const id = userIds[i];
                xmppServerMock.userLeft(id);
                userData.shift();
            }

            await delay(WAIT_FOR_CHANNELS);

            const remainingParticipantsCount =
                initialParticipantCount - leftParticipantsNumber;

            // participants should update their key leftParticipantsNumber times
            // (plus the initial update that set their keys)
            userData.forEach((user) => {
                verify(user.olmSpy.updateMyKeys()).times(
                    1 + leftParticipantsNumber,
                );
            });

            verifyParticipantNumber(xmppServerMock, remainingParticipantsCount);
            verifySasValues(xmppServerMock);
        },
        MAX_TEST_TIME,
    );

    it(
        "participants should sucessfully join and leave an ongoing e2e meeting",
        async () => {
            const initialParticipantCount = 1;
            const joinedParticipantsNumber = 4;
            const leftParticipantsNumber = 2;
            expect(initialParticipantCount).toBeGreaterThan(0);
            expect(joinedParticipantsNumber).toBeGreaterThan(0);
            expect(
                initialParticipantCount + joinedParticipantsNumber,
            ).toBeGreaterThan(leftParticipantsNumber);

            const { xmppServerMock, userData } = await createGroupMeeting(
                initialParticipantCount,
            );
            expect(userData.length).toBe(initialParticipantCount);

            xmppServerMock.enableE2E();

            await delay(WAIT_FOR_CHANNELS);

            verifyParticipantNumber(xmppServerMock, initialParticipantCount);
            verifySasValues(xmppServerMock);

            for (let i = 0; i < joinedParticipantsNumber; i++) {
                const { id, keyHandler } =
                    await createInitializedManagedKeyHandler(
                        xmppServerMock,
                        TEST_TIMEOUT,
                    );
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
                await delay(WAIT_TO_AVOID_SAME_ID);
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

            await delay(WAIT_FOR_CHANNELS);

            // initial participants should ratchet their keys joinedParticipantsNumber times
            // joining participants should ratchet their keys as many times as people joined after them
            //
            // all participants should update their key leftParticipantsNumber times
            // (plus the initial update that set their keys)
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
        },
        MAX_TEST_TIME,
    );

    it(
        "participants should sucessfully leave and join an ongoing e2e meeting",
        async () => {
            const initialParticipantCount = 4;
            const joinedParticipantsNumber = 4;
            const leftParticipantsNumber = 2;
            expect(initialParticipantCount).toBeGreaterThan(0);
            expect(joinedParticipantsNumber).toBeGreaterThan(0);
            expect(initialParticipantCount).toBeGreaterThanOrEqual(
                leftParticipantsNumber,
            );

            const { xmppServerMock, userData } = await createGroupMeeting(
                initialParticipantCount,
            );
            expect(userData.length).toBe(initialParticipantCount);

            xmppServerMock.enableE2E();

            await delay(WAIT_FOR_CHANNELS);

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
                    await createInitializedManagedKeyHandler(
                        xmppServerMock,
                        TEST_TIMEOUT,
                    );
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
                await delay(WAIT_TO_AVOID_SAME_ID);
            }

            const remainingParticipantsCount =
                initialParticipantCount -
                leftParticipantsNumber +
                joinedParticipantsNumber;
            expect(userData.length).toBe(remainingParticipantsCount);

            await delay(WAIT_FOR_CHANNELS);

            // initial participants should ratchet their keys joinedParticipantsNumber times
            // joining participants should ratchet their keys as many times as people joined after them
            //
            // initial participants should update their key leftParticipantsNumber times
            // (plus the initial update that set their keys)
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
        },
        MAX_TEST_TIME,
    );

    it(
        "should sucessfully enable, disable and enable again e2e for a group meeting",
        async () => {
            const participantCount = 3;
            expect(participantCount).toBeGreaterThan(0);

            const { xmppServerMock, userData } =
                await createGroupMeeting(participantCount);
            expect(userData.length).toBe(participantCount);

            xmppServerMock.enableE2E();

            await delay(WAIT_FOR_CHANNELS);

            verifyAllChannels(userData);
            verifyParticipantNumber(xmppServerMock, participantCount);
            verifySasValues(xmppServerMock);

            xmppServerMock.disableE2E();

            await delay(WAIT_FOR_CHANNELS);

            xmppServerMock.enableE2E();

            await delay(WAIT_FOR_CHANNELS);

            verifyAllChannels(userData, 1);
            verifyParticipantNumber(xmppServerMock, participantCount);
            verifySasValues(xmppServerMock);
        },
        MAX_TEST_TIME,
    );

    it(
        "participants should sucessfully join and leave an e2e meeting one after another",
        async () => {
            const joinedParticipantsNumber = 4;
            const leftParticipantsNumber = 2;
            expect(leftParticipantsNumber).toBeLessThanOrEqual(
                joinedParticipantsNumber,
            );
            expect(joinedParticipantsNumber).toBeGreaterThan(0);
            expect(
                joinedParticipantsNumber + leftParticipantsNumber,
            ).toBeLessThan(10);

            const { xmppServerMock, userData } = await createGroupMeeting(1);

            xmppServerMock.enableE2E();
            await delay(WAIT_FOR_CHANNELS);

            for (let i = 0; i < joinedParticipantsNumber; i++) {
                const { id, keyHandler } =
                    await createInitializedManagedKeyHandler(
                        xmppServerMock,
                        TEST_TIMEOUT,
                    );
                const olmSpy = spy(keyHandler._olmAdapter);
                const e2eeSpy = spy(keyHandler.e2eeCtx);
                const keyHandlerSpy = spy(keyHandler);
                userData.push({
                    index: 1 + i,
                    id,
                    keyHandlerSpy,
                    olmSpy,
                    e2eeSpy,
                });

                xmppServerMock.userJoined(keyHandler);
                await delay(WAIT_FOR_CHANNELS);
            }
            expect(userData.length).toBe(1 + joinedParticipantsNumber);

            // meeting participants should ratchet their key as many times as number of user joined after them
            userData.forEach((user) => {
                const x = joinedParticipantsNumber - user.index;
                const times =
                    x > joinedParticipantsNumber ? joinedParticipantsNumber : x;
                verify(user.olmSpy.ratchetMyKeys()).times(times);
            });

            const userIds = xmppServerMock.getAllParticipantsIDs();
            for (let i = 0; i < leftParticipantsNumber; i++) {
                const id = userIds[i];
                xmppServerMock.userLeft(id);
                userData.shift();
                await delay(WAIT_FOR_CHANNELS);
            }

            // meeting participants should update their key as many times as number of left participants
            // (plus the initial update that set their keys)
            userData.forEach((user) => {
                verify(user.olmSpy.updateMyKeys()).times(
                    1 + leftParticipantsNumber,
                );
            });

            verifyParticipantNumber(
                xmppServerMock,
                1 + joinedParticipantsNumber - leftParticipantsNumber,
            );
            verifySasValues(xmppServerMock);
        },
        MAX_TEST_TIME,
    );
});
