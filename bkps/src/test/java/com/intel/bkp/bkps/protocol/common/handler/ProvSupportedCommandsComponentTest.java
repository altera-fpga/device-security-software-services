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

package com.intel.bkp.bkps.protocol.common.handler;

import com.intel.bkp.bkps.domain.AesKey;
import com.intel.bkp.bkps.domain.ConfidentialData;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.exception.CommandNotSupportedException;
import com.intel.bkp.bkps.exception.InvalidConfigurationException;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.bkps.rest.provisioning.service.IServiceConfiguration;
import com.intel.bkp.core.psgcertificate.enumerations.KeyWrappingType;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class ProvSupportedCommandsComponentTest {

    private static final Long CFG_ID = 1L;

    @Mock
    private ProvisioningTransferObject transferObject;

    @Mock
    private ProvisioningRequestDTO dto;

    @Mock
    private ServiceConfiguration configuration;

    @Mock
    private ConfidentialData confidentialData;

    @Mock
    private AesKey aesKey;

    @Mock
    private ProvisioningHandler successor;

    @InjectMocks
    private ProvSupportedCommandsComponent sut;

    private final IServiceConfiguration CONFIGURATION = new IServiceConfiguration() {
        @Override
        public ServiceConfiguration getConfiguration(Long cfgId) {
            return configuration;
        }

        @Override
        public int getConfigurationAndUpdate(Long cfgId) {
            return 0;
        }
    };
    private final IServiceConfiguration NULL_CONFIGURATION = new IServiceConfiguration() {
        @Override
        public ServiceConfiguration getConfiguration(Long cfgId) {
            return null;
        }

        @Override
        public int getConfigurationAndUpdate(Long cfgId) {
            return 0;
        }
    };

    @BeforeEach
    void setUp() {
        sut.setSuccessor(successor);
        when(transferObject.getDto()).thenReturn(dto);
        when(transferObject.getConfigurationCallback()).thenReturn(CONFIGURATION);
        when(dto.getCfgId()).thenReturn(CFG_ID);
    }

    @Test
    void handle_NoCommandSupported_Throws() {
        // given
        mockNoSupportedCommands();

        // when-then
        runAndVerifyCommandNotSupported();
    }

    @Test
    void verify_Success() {
        // given
        mockAesKeyEfuses();
        mockGetSupportedCommands();

        // when
        sut.handle(transferObject);

        // then
        ProvHandlerTestUtil.verifySuccessorCalled(successor, transferObject);
    }

    @Test
    void verify_WithKeyWrapping_Success() {
        // given
        mockAesKeyPufss();
        mockGetSupportedCommandsForKeyWrapping();

        // when
        sut.handle(transferObject);

        // then
        ProvHandlerTestUtil.verifySuccessorCalled(successor, transferObject);
    }

    @Test
    void verify_WithKeyWrappingButQuartusDoesNotSupportPushWrappedKey_ThrowsNotSupported() {
        // given
        mockAesKeyPufss();
        mockGetSupportedCommands();

        // when-then
        runAndVerifyCommandNotSupported();
    }

    @Test
    void verify_ConfigurationIsNull_Fail() {
        // given
        mockGetSupportedCommands();
        when(transferObject.getConfigurationCallback()).thenReturn(NULL_CONFIGURATION);

        // when-then
        runAndVerifyInvalidConfiguration();
    }

    @Test
    void verify_ConfidentialDataIsNull_Fail() {
        // given
        mockGetSupportedCommands();
        when(configuration.getConfidentialData()).thenReturn(null);

        // when-then
        runAndVerifyInvalidConfiguration();
    }

    private void mockAesKeyEfuses() {
        when(configuration.getConfidentialData()).thenReturn(confidentialData);
        when(confidentialData.getAesKey()).thenReturn(aesKey);
        when(aesKey.getStorage()).thenReturn(StorageType.EFUSES);
        when(aesKey.getKeyWrappingType()).thenReturn(KeyWrappingType.INTERNAL);
    }

    private void mockAesKeyPufss() {
        when(configuration.getConfidentialData()).thenReturn(confidentialData);
        when(confidentialData.getAesKey()).thenReturn(aesKey);
        when(aesKey.getStorage()).thenReturn(StorageType.PUFSS);
        when(aesKey.getKeyWrappingType()).thenReturn(KeyWrappingType.UDS_IID_PUF);
    }

    private void runAndVerifyCommandNotSupported() {
        ProvHandlerTestUtil.runAndVerifyException(sut, transferObject, CommandNotSupportedException.class);
    }

    private void runAndVerifyInvalidConfiguration() {
        ProvHandlerTestUtil.runAndVerifyException(sut, transferObject, InvalidConfigurationException.class);
    }

    private void mockNoSupportedCommands() {
        when(dto.getSupportedCommands()).thenReturn(0);
    }

    private void mockGetSupportedCommands() {
        when(dto.getSupportedCommands()).thenReturn(1); // SEND_PACKET
    }

    private void mockGetSupportedCommandsForKeyWrapping() {
        when(dto.getSupportedCommands()).thenReturn(3); // SEND_PACKET, PUSH_WRAPPED_KEY
    }
}
