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

package com.intel.bkp.bkps.programmer.sigma;

import com.intel.bkp.bkps.exception.PufActivationPufTypeNotSupported;
import com.intel.bkp.bkps.programmer.model.MessageType;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.core.psgcertificate.enumerations.KeyWrappingType;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import org.junit.jupiter.api.Test;
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
import static com.intel.bkp.core.manufacturing.model.PufType.EFUSE;
import static com.intel.bkp.core.manufacturing.model.PufType.IID;
import static com.intel.bkp.core.manufacturing.model.PufType.IIDUSER;
import static com.intel.bkp.core.manufacturing.model.PufType.INTEL;
import static com.intel.bkp.core.manufacturing.model.PufType.INTEL_USER;
import static com.intel.bkp.core.psgcertificate.enumerations.StorageType.BBRAM;
import static com.intel.bkp.core.psgcertificate.enumerations.StorageType.EFUSES;
import static com.intel.bkp.core.psgcertificate.enumerations.StorageType.PUFSS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SupportedMessageTypesFactoryTest {

    private static Stream<Arguments> getForKeyWrappingParams() {
        return Stream.of(
            Arguments.of(EFUSES, KeyWrappingType.NOWRAP, List.of()),
            Arguments.of(BBRAM, KeyWrappingType.NOWRAP, List.of()),
            Arguments.of(PUFSS, KeyWrappingType.INTERNAL, List.of(PUSH_WRAPPED_KEY)),
            Arguments.of(PUFSS, KeyWrappingType.USER_IID_PUF, List.of(PUSH_WRAPPED_KEY, PUSH_WRAPPED_KEY_USER_IID)),
            Arguments.of(PUFSS, KeyWrappingType.UDS_IID_PUF, List.of(PUSH_WRAPPED_KEY, PUSH_WRAPPED_KEY_UDS_IID))
        );
    }

    private static Stream<Arguments> getForPufActivateParams() {
        return Stream.of(
            Arguments.of(IID, PUSH_HELPER_DATA_UDS_IID),
            Arguments.of(INTEL, PUSH_HELPER_DATA_UDS_INTEL)
        );
    }

    private static Stream<Arguments> getForPufActivateUnsupportedParams() {
        return Stream.of(
            Arguments.of(EFUSE),
            Arguments.of(IIDUSER),
            Arguments.of(INTEL_USER)
        );
    }

    @ParameterizedTest
    @MethodSource("getForKeyWrappingParams")
    void getForKeyWrapping_Success(StorageType aesKeyStorage, KeyWrappingType keyWrappingType,
                                   List<MessageType> expectedMessageTypes) {
        // when
        final List<MessageType> result = SupportedMessageTypesFactory.getForKeyWrapping(aesKeyStorage, keyWrappingType);

        // then
        assertIterableEquals(expectedMessageTypes, result);
    }

    @ParameterizedTest
    @MethodSource("getForPufActivateParams")
    void getForPufActivate_Success(PufType pufType, MessageType expectedMessageType) {
        // when
        final MessageType result = SupportedMessageTypesFactory.getForPufActivate(pufType);

        // then
        assertEquals(expectedMessageType, result);
    }

    @ParameterizedTest
    @MethodSource("getForPufActivateUnsupportedParams")
    void getForPufActivate_UnsupportedPufType_Throws(PufType pufType) {
        // when-then
        assertThrows(PufActivationPufTypeNotSupported.class,
            () -> SupportedMessageTypesFactory.getForPufActivate(pufType));
    }

    @Test
    void getRequired_ReturnsSendPacket() {
        // when
        final List<MessageType> result = SupportedMessageTypesFactory.getRequired();

        // then
        assertIterableEquals(List.of(SEND_PACKET), result);
    }
}
