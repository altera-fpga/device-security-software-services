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
import com.intel.bkp.bkps.domain.AesKey;
import com.intel.bkp.bkps.domain.AttestationConfiguration;
import com.intel.bkp.bkps.domain.ConfidentialData;
import com.intel.bkp.bkps.domain.EfusesPublic;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.domain.enumeration.ImportMode;
import com.intel.bkp.bkps.exception.InvalidConfigurationException;
import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.protocol.common.handler.ProvHandlerTestUtil;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.sigma.model.ProvContextEnc;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.bkps.rest.provisioning.service.IServiceConfiguration;
import com.intel.bkp.command.messages.common.VolatileAesErase;
import com.intel.bkp.command.messages.sigma.SigmaEncMessage;
import com.intel.bkp.command.messages.sigma.SigmaEncMessageBuilder;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.test.KeyGenUtils;
import com.intel.bkp.test.RandomUtils;
import lombok.SneakyThrows;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.nio.ByteBuffer;
import java.util.concurrent.ThreadLocalRandom;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class ProvEncClearBbramComponentTest {

    private static final byte[] VOLATILE_AES_ERASE = new byte[]{1, 2};
    private static final byte[] SIGMA_ENC = new byte[]{3, 4};
    private static final String DEFAULT_NAME = "AAAAAAAAAA";
    private static final PufType DEFAULT_PUF_TYPE = PufType.EFUSE;

    private static final Integer DEFAULT_OVERBUILD_MAX = 1;
    private static final String DEFAULT_EFUSES_PUB_MASK =
        Hex.toHexString(ByteBuffer.allocate(256).putLong(151).putInt(8).array());
    private static final String DEFAULT_EFUSES_PUB_VALUE =
        Hex.toHexString(ByteBuffer.allocate(256).putLong(132).putInt(8).array());

    @Mock
    private AesGcmContextProviderImpl contextEncryptionProvider;

    @Mock
    private ProvisioningTransferObject transferObject;

    @Mock
    private ProvisioningRequestDTO dto;

    @Mock
    private ProvisioningRequestDTOReader dtoReader;

    @Mock
    private ProvisioningHandler successor;

    @Mock
    private IServiceConfiguration iServiceConfiguration;

    @Mock
    private CommandLayer commandLayer;

    @InjectMocks
    private ProvEncClearBbramComponent sut;

    @BeforeEach
    void setUp() {
        sut.setSuccessor(successor);
        when(transferObject.getDtoReader()).thenReturn(dtoReader);
        when(transferObject.getDto()).thenReturn(dto);
        when(transferObject.getConfigurationCallback()).thenReturn(iServiceConfiguration);
        when(dto.getCfgId()).thenReturn(1L);
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
    void handle_VerifyPerformCalled() throws Exception {
        // given
        prepareCommands();
        mockFlowStage(FlowStage.SIGMA_AUTH_DATA);
        mockValidRecoverProvisioningContext();
        when(iServiceConfiguration.getConfiguration(anyLong()))
            .thenReturn(prepareServiceConfiguration());
        mockCreatingJtagResponse();
        mockContextEncrypt();

        // when
        sut.handle(transferObject);

        // then
        ProvHandlerTestUtil.verifySuccessorNeverCalled(successor, transferObject);
    }

    @Test
    void handle_VerifyPerformCalled_ThrowsException() throws Exception {
        // given
        mockFlowStage(FlowStage.SIGMA_AUTH_DATA);
        mockValidRecoverProvisioningContext();

        // when-then
        ProvHandlerTestUtil.runAndVerifyException(sut, transferObject, InvalidConfigurationException.class);
    }

    @Test
    void handle_VerifyPerformCalledAndWrongContext_ThrowsException() throws Exception {
        // given
        mockFlowStage(FlowStage.SIGMA_AUTH_DATA);
        mockInvalidRecoverProvisioningContext();
        when(iServiceConfiguration.getConfiguration(anyLong()))
            .thenReturn(prepareServiceConfiguration());

        // when-then
        ProvHandlerTestUtil.runAndVerifyException(sut, transferObject, ProvisioningGenericException.class);
    }

    private void prepareCommands() {
        when(commandLayer.create(any(VolatileAesErase.class), eq(CommandIdentifier.VOLATILE_AES_ERASE)))
            .thenReturn(VOLATILE_AES_ERASE);
        when(commandLayer.create(any(SigmaEncMessage.class), eq(CommandIdentifier.SIGMA_ENC)))
            .thenReturn(SIGMA_ENC);
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

    private ServiceConfiguration prepareServiceConfiguration() throws KeystoreGenericException {
        ConfidentialData confidentialData = new ConfidentialData();
        confidentialData.setImportMode(ImportMode.PLAINTEXT);
        AesKey aesKey = new AesKey();
        aesKey.setStorage(StorageType.BBRAM);
        aesKey.setValue(Hex.toHexString(KeyGenUtils.genAes256().getEncoded()));
        confidentialData.setAesKey(aesKey);
        AttestationConfiguration attestationConfig = new AttestationConfiguration();
        EfusesPublic efusesPub = new EfusesPublic();
        efusesPub.setMask(DEFAULT_EFUSES_PUB_MASK);
        efusesPub.setValue(DEFAULT_EFUSES_PUB_VALUE);
        attestationConfig.setEfusesPublic(efusesPub);

        return new ServiceConfiguration()
            .name(DEFAULT_NAME)
            .pufType(DEFAULT_PUF_TYPE)
            .overbuildMax(DEFAULT_OVERBUILD_MAX)
            .overbuildCurrent(2)
            .confidentialData(confidentialData)
            .attestationConfig(attestationConfig);
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
