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

import com.intel.bkp.bkps.crypto.aesctr.AesCtrSigmaEncProviderImpl;
import com.intel.bkp.bkps.crypto.aesgcm.AesGcmContextProviderImpl;
import com.intel.bkp.bkps.crypto.hmac.HMacSigmaEncProviderImpl;
import com.intel.bkp.bkps.domain.AesKey;
import com.intel.bkp.bkps.domain.ConfidentialData;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.dto.ResponseDTO;
import com.intel.bkp.bkps.protocol.common.EncryptedPayload;
import com.intel.bkp.bkps.protocol.common.handler.ProvHandlerTestUtil;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.common.model.ProtocolType;
import com.intel.bkp.bkps.protocol.sigma.TempAesGcmContextProviderImpl;
import com.intel.bkp.bkps.protocol.sigma.model.ProvContextEnc;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ContextDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTOBuilder;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.bkps.rest.provisioning.service.IServiceConfiguration;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.command.responses.sigma.SigmaEncFlowType;
import com.intel.bkp.command.responses.sigma.SigmaEncResponseBuilder;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.psgcertificate.enumerations.KeyWrappingType;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.crypto.exceptions.HMacProviderException;
import com.intel.bkp.test.JtagUtils;
import com.intel.bkp.test.RandomUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;

import static com.intel.bkp.test.AssertionUtils.verifyExpectedErrorCode;
import static com.intel.bkp.utils.ByteConverter.toBytes;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class ProvProvisionComponentTest {

    private static final Long CFG_ID = 1L;
    private static final byte[] DEVICE_ID = RandomUtils.generateDeviceId();
    private static final int MSG_RESP_COUNTER = 1;
    private static final byte[] MSG_RESP_COUNTER_BYTES = toBytes(MSG_RESP_COUNTER);
    private final byte[] sessionEncryptionKey = RandomUtils.generateRandomBytes(32);
    private final byte[] sessionMacKey = RandomUtils.generateRandomBytes(32);
    private final byte[] sdmSessionId = RandomUtils.generateRandomBytes(4);
    private final byte[] initialIv =
        new byte[]{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    private final byte[] initialIvPlusMessageResponseCounter =
        new byte[]{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02};
    private final TempAesGcmContextProviderImpl contextProvider = new TempAesGcmContextProviderImpl();

    @Mock
    private AesGcmContextProviderImpl contextEncryptionProvider;

    @Mock
    private ServiceConfiguration serviceConfiguration;

    @Mock
    private ConfidentialData confidentialData;

    @Mock
    private AesKey aesKey;

    @Mock
    private ProvisioningTransferObject transferObject;

    @Mock
    private ProvisioningRequestDTOReader dtoReaderMock;

    @Mock
    private ProvisioningHandler successor;

    @Mock
    private CommandLayer commandLayer;

    @InjectMocks
    private ProvProvisionComponent sut;

    private final IServiceConfiguration SERVICE_CONFIGURATION = new IServiceConfiguration() {
        @Override
        public ServiceConfiguration getConfiguration(Long cfgId) {
            return serviceConfiguration;
        }

        @Override
        public int getConfigurationAndUpdate(Long cfgId) {
            return 0;
        }
    };

    @BeforeEach
    void setUp() throws EncryptionProviderException {
        sut.setSuccessor(successor);
        when(transferObject.getConfigurationCallback()).thenReturn(SERVICE_CONFIGURATION);
        when(serviceConfiguration.getConfidentialData()).thenReturn(confidentialData);
        when(confidentialData.getAesKey()).thenReturn(aesKey);
        when(aesKey.getStorage()).thenReturn(StorageType.EFUSES);
        when(commandLayer.create(any(), eq(CommandIdentifier.SIGMA_TEARDOWN)))
            .thenReturn(new byte[]{4, 5, 6});
        when(contextEncryptionProvider.encrypt(any())).thenReturn(new byte[]{1, 2, 3});
    }

    @Test
    void handle_WithNotSupportedFlowStage_VerifySuccessorCalled() {
        // given
        when(dtoReaderMock.getFlowStage()).thenReturn(FlowStage.SIGMA_CREATE_SESSION);
        when(transferObject.getDtoReader()).thenReturn(dtoReaderMock);

        // when
        sut.handle(transferObject);

        // then
        ProvHandlerTestUtil.verifySuccessorCalled(successor, transferObject);
    }

    @Test
    void handle_Success() throws Exception {
        // given
        prepareContextEncryptionProvider();
        final byte[] sigmaEncResponse = getSigmaEncResponse(prepareSigmaEncCommandsResponseWithStatusSuccess());
        mockCommand(sigmaEncResponse);

        // when
        final ProvisioningResponseDTO result = sut.handle(transferObject);

        // then
        assertEquals(1, result.getJtagCommands().size());
    }

    @Test
    void handle_CertificateProcessStatusFailed_Throws() throws Exception {
        // given
        prepareContextEncryptionProvider();
        final byte[] sigmaEncResponse = getSigmaEncResponse(prepareSigmaEncCommandsResponseWithStatusFailed());
        mockCommand(sigmaEncResponse);
        when(aesKey.getStorage()).thenReturn(StorageType.EFUSES);

        // when-then
        assertThrows(ProvisioningGenericException.class, () -> sut.handle(transferObject));
    }

    @Test
    void handle_WithKeyWrapping_Success() throws Exception {
        // given
        prepareContextEncryptionProvider();
        final byte[] sigmaEncResponse = getSigmaEncResponse(prepareSigmaEncCommandsResponseWithStatusSuccess());
        mockCommand(sigmaEncResponse);
        when(aesKey.getStorage()).thenReturn(StorageType.PUFSS);
        when(aesKey.getKeyWrappingType()).thenReturn(KeyWrappingType.USER_IID_PUF);

        // when
        final ProvisioningResponseDTO result = sut.handle(transferObject);

        // then
        assertEquals(2, result.getJtagCommands().size());
    }

    @Test
    void handle_WithSigmaEncHeaderOnly_Success() throws Exception {
        // given
        prepareContextEncryptionProvider();
        final byte[] sigmaEncResponseHeaderOnly = getSigmaEncResponseHeaderOnly();
        mockCommand(sigmaEncResponseHeaderOnly);

        // when
        final ProvisioningResponseDTO result = sut.handle(transferObject);

        // then
        assertEquals(1, result.getJtagCommands().size());
    }

    @Test
    void handle_WithCorrectFlowStageFirstAndWrongContext_ThrowsException() throws Exception {
        // given
        when(dtoReaderMock.getFlowStage()).thenReturn(FlowStage.SIGMA_ENC_ASSET);
        when(dtoReaderMock.read(ProvContextEnc.class)).thenThrow(ProvisioningConverterException.class);
        when(transferObject.getDtoReader()).thenReturn(dtoReaderMock);

        // when-then
        ProvHandlerTestUtil.runAndVerifyException(sut, transferObject, ProvisioningGenericException.class);
    }

    @Test
    void handle_WithInvalidJtagResponses_ThrowsException() throws Exception {
        // given
        prepareContextEncryptionProvider();
        ProvisioningRequestDTO dto = new ProvisioningRequestDTO();
        dto.setContext(generateEncodedContext());
        dto.setJtagResponses(new ArrayList<>());
        ProvisioningRequestDTOReader dtoReader =
            new ProvisioningRequestDTOReader(contextEncryptionProvider, dto);
        when(transferObject.getDtoReader()).thenReturn(dtoReader);

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.handle(transferObject)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.PROVISIONING_GENERIC_EXCEPTION);
    }

    private ProvisioningRequestDTOReader prepareRequestDTOReader(byte[] sigmaEncResponse)
        throws Exception {
        ProvisioningRequestDTO dto = new ProvisioningRequestDTO();
        dto.setContext(generateEncodedContext());
        dto.setSupportedCommands(2);
        dto.setJtagResponses(Collections.singletonList(ResponseDTO.from(sigmaEncResponse)));
        return new ProvisioningRequestDTOReader(contextEncryptionProvider, dto);
    }

    private void prepareContextEncryptionProvider() throws EncryptionProviderException {
        when(contextEncryptionProvider.decrypt(any())).thenAnswer(invocation -> {
            byte[] decodedContext = invocation.getArgument(0);
            return contextProvider.decrypt(decodedContext);
        });
    }

    private byte[] getSigmaEncResponse(byte[] sigmaEncCommandsResponseBytes) throws HMacProviderException {
        SigmaEncResponseBuilder builder = new SigmaEncResponseBuilder();
        builder.setFlowType(SigmaEncFlowType.WITH_ENCRYPTED_RESPONSE);
        builder.setSdmSessionId(sdmSessionId);
        builder.setMessageResponseCounter(MSG_RESP_COUNTER_BYTES);
        builder.setInitialIv(initialIv);
        builder.setEncryptedPayload(sigmaEncCommandsResponseBytes);
        builder.setPayloadLen(sigmaEncCommandsResponseBytes.length);
        builder.setMac(prepareValidMac(builder.withActor(EndiannessActor.FIRMWARE).getDataToMac()));
        builder.withActor(EndiannessActor.FIRMWARE);
        return builder.build().array();
    }

    private byte[] getSigmaEncResponseHeaderOnly() {
        SigmaEncResponseBuilder builder = new SigmaEncResponseBuilder();
        builder.setFlowType(SigmaEncFlowType.HEADER_ONLY);
        builder.withActor(EndiannessActor.FIRMWARE);
        return builder.build().array();
    }

    private byte[] prepareSigmaEncCommandsResponseWithStatusFailed()
        throws EncryptionProviderException {
        return prepareSigmaEncCommandsResponseWithStatus(false);
    }

    private byte[] prepareSigmaEncCommandsResponseWithStatusSuccess()
        throws EncryptionProviderException {
        return prepareSigmaEncCommandsResponseWithStatus(true);
    }

    private byte[] prepareSigmaEncCommandsResponseWithStatus(boolean success)
        throws EncryptionProviderException {

        byte[] certificateProcessStatus = toBytes(success ? 0 : 1);
        byte[] data = RandomUtils.generateRandomBytes(120);

        final byte[] header = JtagUtils.prepareValidHeader(data.length);
        final byte[] command =
            ByteBuffer.allocate(certificateProcessStatus.length + data.length)
                .put(certificateProcessStatus)
                .put(data)
                .array();

        final byte[] commandWithHeader =
            ByteBuffer.allocate(Integer.BYTES + command.length)
                .put(header)
                .put(command)
                .array();

        byte[] sigmaEncCommandsResponseBytes = new EncryptedPayload(commandWithHeader, new byte[0]).build();

        when(commandLayer.retrieve(commandWithHeader, CommandIdentifier.CERTIFICATE)).thenReturn(command);

        return new AesCtrSigmaEncProviderImpl(sessionEncryptionKey, () -> initialIvPlusMessageResponseCounter)
            .encrypt(sigmaEncCommandsResponseBytes);
    }

    private byte[] prepareValidMac(byte[] dataToMac) throws HMacProviderException {
        return new HMacSigmaEncProviderImpl(sessionMacKey).getHash(dataToMac);
    }

    private ContextDTO generateEncodedContext() throws Exception {
        return new ProvisioningResponseDTOBuilder()
            .context(getProvContext())
            .flowStage(FlowStage.SIGMA_ENC_ASSET)
            .protocolType(ProtocolType.SIGMA)
            .withMessages(new ArrayList<>())
            .encryptionProvider(contextProvider)
            .build()
            .getContext();
    }

    private ProvContextEnc getProvContext() {
        return new ProvContextEnc(CFG_ID, DEVICE_ID, sessionEncryptionKey, sessionMacKey, initialIv, new byte[]{}, 0);
    }

    private void mockCommand(byte[] sigmaEncResponse) throws Exception {
        ProvisioningRequestDTOReader dtoReader = prepareRequestDTOReader(sigmaEncResponse);
        when(transferObject.getDtoReader()).thenReturn(dtoReader);
        when(commandLayer.retrieve(sigmaEncResponse, CommandIdentifier.SIGMA_ENC)).thenReturn(sigmaEncResponse);
    }
}
