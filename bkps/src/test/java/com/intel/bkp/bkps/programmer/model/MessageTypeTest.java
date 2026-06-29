/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2026 Altera Corporation. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * **************************************************************************
 */

package com.intel.bkp.bkps.programmer.model;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static com.intel.bkp.bkps.programmer.model.MessageType.PUSH_HELPER_DATA_UDS_IID;
import static com.intel.bkp.bkps.programmer.model.MessageType.PUSH_HELPER_DATA_UDS_INTEL;
import static com.intel.bkp.bkps.programmer.model.MessageType.PUSH_WRAPPED_KEY;
import static com.intel.bkp.bkps.programmer.model.MessageType.PUSH_WRAPPED_KEY_UDS_IID;
import static com.intel.bkp.bkps.programmer.model.MessageType.PUSH_WRAPPED_KEY_USER_IID;
import static com.intel.bkp.bkps.programmer.model.MessageType.SEND_PACKET;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MessageTypeTest {

    private static Stream<Arguments> getParamsAreSetInSuccess() {
        return Stream.of(
            Arguments.of(List.of(), 0),
            Arguments.of(List.of(), 1),
            Arguments.of(List.of(SEND_PACKET), 1),
            Arguments.of(List.of(SEND_PACKET), 3),
            Arguments.of(List.of(SEND_PACKET, PUSH_WRAPPED_KEY_USER_IID), 5),
            Arguments.of(List.of(SEND_PACKET, PUSH_WRAPPED_KEY_UDS_IID), 9),
            Arguments.of(List.of(PUSH_HELPER_DATA_UDS_IID, PUSH_WRAPPED_KEY_UDS_IID, PUSH_HELPER_DATA_UDS_INTEL), 56)
        );
    }

    private static Stream<Arguments> getParamsAreSetInNotSupported() {
        return Stream.of(
            Arguments.of(List.of(SEND_PACKET), 2),
            Arguments.of(List.of(SEND_PACKET), 4),
            Arguments.of(List.of(SEND_PACKET, PUSH_WRAPPED_KEY_UDS_IID), 6),
            Arguments.of(List.of(PUSH_HELPER_DATA_UDS_IID, PUSH_WRAPPED_KEY_UDS_IID, PUSH_HELPER_DATA_UDS_INTEL), 2)
        );
    }

    private static Stream<Arguments> getParamsAtLeastOneIsSetInSuccess() {
        return Stream.of(
            Arguments.of(List.of(), 0),
            Arguments.of(List.of(), 1),
            Arguments.of(List.of(PUSH_WRAPPED_KEY), 2),
            Arguments.of(List.of(PUSH_WRAPPED_KEY), 14),
            Arguments.of(List.of(PUSH_WRAPPED_KEY_USER_IID), 14),
            Arguments.of(List.of(PUSH_WRAPPED_KEY_UDS_IID), 14),
            Arguments.of(List.of(PUSH_WRAPPED_KEY, PUSH_WRAPPED_KEY_USER_IID, PUSH_WRAPPED_KEY_UDS_IID), 3),
            Arguments.of(List.of(PUSH_WRAPPED_KEY, PUSH_WRAPPED_KEY_USER_IID, PUSH_WRAPPED_KEY_UDS_IID), 4),
            Arguments.of(List.of(PUSH_WRAPPED_KEY, PUSH_WRAPPED_KEY_USER_IID, PUSH_WRAPPED_KEY_UDS_IID), 14)
        );
    }

    private static Stream<Arguments> getParamsAtLeastOneIsSetInNotSupported() {
        return Stream.of(
            Arguments.of(List.of(PUSH_WRAPPED_KEY), 1),
            Arguments.of(List.of(PUSH_WRAPPED_KEY_USER_IID), 2),
            Arguments.of(List.of(PUSH_WRAPPED_KEY_UDS_IID), 2),
            Arguments.of(List.of(PUSH_WRAPPED_KEY, PUSH_WRAPPED_KEY_USER_IID, PUSH_WRAPPED_KEY_UDS_IID), 16)
        );
    }

    @ParameterizedTest
    @MethodSource("getParamsAreSetInSuccess")
    void areSetIn_Success(List<MessageType> expectedCommandsList, int supportedCommands) {
        // when
        final boolean result = MessageType.areSetIn(expectedCommandsList, supportedCommands);

        // then
        assertTrue(result);
    }

    @ParameterizedTest
    @MethodSource("getParamsAreSetInNotSupported")
    void areSetIn_ReturnsFalse(List<MessageType> expectedCommandsList, int supportedCommands) {
        // when
        final boolean result = MessageType.areSetIn(expectedCommandsList, supportedCommands);

        // then
        assertFalse(result);
    }

    @ParameterizedTest
    @MethodSource("getParamsAtLeastOneIsSetInSuccess")
    void atLeastOneIsSetIn_Success(List<MessageType> expectedCommandsList, int supportedCommands) {
        // when
        final boolean result = MessageType.atLeastOneIsSetIn(expectedCommandsList, supportedCommands);

        // then
        assertTrue(result);
    }

    @ParameterizedTest
    @MethodSource("getParamsAtLeastOneIsSetInNotSupported")
    void atLeastOneIsSetIn_ReturnsFalse(List<MessageType> expectedCommandsList, int supportedCommands) {
        // when
        final boolean result = MessageType.atLeastOneIsSetIn(expectedCommandsList, supportedCommands);

        // then
        assertFalse(result);
    }
}
