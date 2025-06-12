/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2025 Altera Corporation. All Rights Reserved.
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

package com.intel.bkp.bkps.protocol.sigma.wrapping;

import com.intel.bkp.bkps.domain.AesKey;
import com.intel.bkp.bkps.domain.ConfidentialData;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.exception.InvalidConfigurationException;
import com.intel.bkp.bkps.programmer.model.MessageType;
import com.intel.bkp.bkps.rest.provisioning.service.IServiceConfiguration;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.psgcertificate.enumerations.KeyWrappingType;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class KeyWrappingManagerTest {

    private static final Long CFG_ID = 1L;

    @Mock
    private ServiceConfiguration serviceConfiguration;

    @Mock
    private ConfidentialData confidentialData;

    @Mock
    private AesKey aesKey;

    @Mock
    private IServiceConfiguration configurationCallback;

    private KeyWrappingManager sut;

    private static Stream<Arguments> getParamsIsKeyWrapping() {
        return Stream.of(
            Arguments.of(StorageType.EFUSES, false),
            Arguments.of(StorageType.BBRAM, false),
            Arguments.of(StorageType.PUFSS, true)
        );
    }

    private static Stream<Arguments> getParamsGetMessageType() {
        return Stream.of(
            Arguments.of(KeyWrappingType.UDS_IID_PUF, MessageType.PUSH_WRAPPED_KEY_UDS_IID),
            Arguments.of(KeyWrappingType.USER_IID_PUF, MessageType.PUSH_WRAPPED_KEY_USER_IID)
        );
    }

    @BeforeEach
    void setUp() {
        when(configurationCallback.getConfiguration(CFG_ID)).thenReturn(serviceConfiguration);
        when(serviceConfiguration.getConfidentialData()).thenReturn(confidentialData);
        when(confidentialData.getAesKey()).thenReturn(aesKey);

        sut = new KeyWrappingManager(configurationCallback, CFG_ID);
    }

    @ParameterizedTest
    @MethodSource("getParamsIsKeyWrapping")
    void isKeyWrapping_Success(StorageType storageType, boolean expectedResult) {
        // given
        when(aesKey.getStorage()).thenReturn(storageType);

        // when
        boolean result = sut.isKeyWrapping();

        // then
        assertEquals(expectedResult, result);
    }

    @ParameterizedTest
    @MethodSource("getParamsGetMessageType")
    void getMessageType_Success(KeyWrappingType keyWrappingType, MessageType expectedMessageType) {
        // given
        final int supportedCommands = 15; // ALL
        when(aesKey.getKeyWrappingType()).thenReturn(keyWrappingType);

        // when
        MessageType result = sut.getMessageType(supportedCommands);

        // then
        assertEquals(expectedMessageType, result);
    }

    @Test
    void getMessageType_WithOnlyLegacyPushWrappedKeySupported_ReturnsPushWrappedKey() {
        // given
        final int supportedCommands = 2; // PUSH_WRAPPED_KEY
        when(aesKey.getKeyWrappingType()).thenReturn(KeyWrappingType.UDS_IID_PUF);

        // when
        MessageType result = sut.getMessageType(supportedCommands);

        // then
        assertEquals(MessageType.PUSH_WRAPPED_KEY, result);
    }

    @Test
    void getMessageType_PushWrappedKeyNotSupported_Throws() {
        // given
        final int supportedCommands = 0;
        when(aesKey.getKeyWrappingType()).thenReturn(KeyWrappingType.UDS_IID_PUF);

        // when-then
        assertThrows(BKPBadRequestException.class, () -> sut.getMessageType(supportedCommands));
    }

    @Test
    void getMessageType_InvalidKeyWrappingType_Throws() {
        // given
        final int supportedCommands = 0;
        when(aesKey.getKeyWrappingType()).thenReturn(KeyWrappingType.INTERNAL);

        // when-then
        assertThrows(InvalidConfigurationException.class, () -> sut.getMessageType(supportedCommands));
    }

}
