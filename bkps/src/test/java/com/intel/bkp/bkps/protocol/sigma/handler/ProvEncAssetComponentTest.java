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

package com.intel.bkp.bkps.protocol.sigma.handler;

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmContextProviderImpl;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.protocol.common.MessagesForSigmaEncPayload;
import com.intel.bkp.bkps.protocol.common.handler.ProvHandlerTestUtil;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.sigma.model.ProvContextEnc;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.bkps.rest.provisioning.service.IServiceConfiguration;
import com.intel.bkp.bkps.rest.provisioning.service.OverbuildCounterManager;
import com.intel.bkp.bkps.rest.provisioning.service.ProvisioningHistoryService;
import com.intel.bkp.command.messages.sigma.SigmaEncMessageBuilder;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.test.KeyGenUtils;
import com.intel.bkp.test.RandomUtils;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.concurrent.ThreadLocalRandom;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class ProvEncAssetComponentTest {

    @Mock
    private AesGcmContextProviderImpl contextEncryptionProvider;

    @Mock
    private MessagesForSigmaEncPayload messagesForSigmaEncPayload;

    @Mock
    private ProvisioningHistoryService provisioningHistoryService;

    @Mock
    private IServiceConfiguration iServiceConfiguration;

    @Mock
    private ProvisioningRequestDTOReader dtoReader;

    @Mock
    private ProvisioningHandler successor;

    @Mock
    private ProvisioningTransferObject transferObject;

    @Mock
    private ServiceConfiguration serviceConfiguration;

    @Mock
    private OverbuildCounterManager overbuildCounterManager;

    @Mock
    private CommandLayer commandLayer;

    @InjectMocks
    private ProvEncAssetComponent sut;

    @BeforeEach
    void setUp() {
        sut.setSuccessor(successor);
        when(transferObject.getDtoReader()).thenReturn(dtoReader);
        when(transferObject.getConfigurationCallback()).thenReturn(iServiceConfiguration);
        when(iServiceConfiguration.getConfiguration(anyLong())).thenReturn(serviceConfiguration);
        when(serviceConfiguration.getPufType()).thenReturn(PufType.EFUSE);
        when(messagesForSigmaEncPayload.prepareFrom(any(ServiceConfiguration.class)))
            .thenReturn(new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11});
    }

    @Test
    void handle_WithNotSupportedFlowStage_VerifySuccessorCalled() {
        // given
        mockFlowStage(FlowStage.SIGMA_CREATE_SESSION);

        // when
        sut.handle(transferObject);

        // then
        ProvHandlerTestUtil.verifySuccessorCalled(successor, transferObject);
    }

    @Test
    void handle_WithCorrectFlowStageFirstPerform_Success() throws Exception {
        // given
        mockFlowStage(FlowStage.SIGMA_AUTH_DATA);
        mockValidRecoverProvisioningContext();
        mockProvisionedStatus();
        mockCreatingJtagResponse();
        mockContextEncrypt();

        // when
        sut.handle(transferObject);

        // then
        ProvHandlerTestUtil.verifySuccessorNeverCalled(successor, transferObject);
        verify(overbuildCounterManager).increment(any(IServiceConfiguration.class), any(Long.class));
    }

    @Test
    void handle_WithCorrectFlowStageSecondPerform_Success() throws Exception {
        // given
        mockFlowStage(FlowStage.SIGMA_ENC);
        mockValidRecoverProvisioningContext();
        mockProvisionedStatus();
        mockCreatingJtagResponse();
        mockContextEncrypt();

        // when
        sut.handle(transferObject);

        // then
        ProvHandlerTestUtil.verifySuccessorNeverCalled(successor, transferObject);
        verify(overbuildCounterManager).increment(any(IServiceConfiguration.class), any(Long.class));
    }

    @Test
    void handle_WithCorrectFlowStageFirstAndWrongContext_ThrowsException() throws Exception {
        // given
        mockFlowStage(FlowStage.SIGMA_AUTH_DATA);
        mockInvalidRecoverProvisioningContext();

        // when-then
        ProvHandlerTestUtil.runAndVerifyException(sut, transferObject, ProvisioningGenericException.class);
    }

    private void mockFlowStage(FlowStage flowStage) {
        when(dtoReader.getFlowStage()).thenReturn(flowStage);
    }

    private void mockValidRecoverProvisioningContext() throws Exception {
        ProvContextEnc provContextEnc = new ProvContextEnc();
        provContextEnc.setCfgId(1L);
        provContextEnc.setSessionEncryptionKey(KeyGenUtils.genAes256().getEncoded());
        byte[] sdmSessionId = new byte[4];
        ThreadLocalRandom.current().nextBytes(sdmSessionId);
        provContextEnc.setSdmSessionId(sdmSessionId);
        byte[] sessionMacKey = new byte[SigmaEncMessageBuilder.MAC_LEN];
        ThreadLocalRandom.current().nextBytes(sessionMacKey);
        provContextEnc.setChipId(RandomUtils.generateDeviceId());
        provContextEnc.setSessionMacKey(sessionMacKey);
        when(dtoReader.read(ProvContextEnc.class)).thenReturn(provContextEnc);
    }

    private void mockInvalidRecoverProvisioningContext() throws Exception {
        when(dtoReader.read(ProvContextEnc.class)).thenThrow(ProvisioningConverterException.class);
    }

    private void mockProvisionedStatus() {
        when(provisioningHistoryService.getCurrentProvisionedStatusAndUpdate(any(), any(PufType.class))).thenReturn(
            true);
    }

    private void mockCreatingJtagResponse() {
        when(commandLayer.create(any(), any()))
            .thenReturn(new byte[]{4, 5, 6});
    }

    @SneakyThrows
    private void mockContextEncrypt() {
        when(contextEncryptionProvider.encrypt(any())).thenReturn(new byte[]{1, 2, 3});
    }
}
