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
import com.intel.bkp.bkps.crypto.hmac.HMacSigmaEncProviderImpl;
import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.model.ResponseStatus;
import com.intel.bkp.bkps.protocol.common.EncryptedPayload;
import com.intel.bkp.bkps.protocol.common.handler.ProvHandlerTestUtil;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.sigma.model.ProvContextEnc;
import com.intel.bkp.bkps.protocol.sigma.session.IMessageResponseCounterProvider;
import com.intel.bkp.bkps.protocol.sigma.session.SecureSessionIvProvider;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.command.messages.sigma.SigmaTeardownMessageBuilder;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.command.responses.sigma.SigmaEncFlowType;
import com.intel.bkp.command.responses.sigma.SigmaEncResponseBuilder;
import com.intel.bkp.core.endianness.EndiannessActor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.ArrayList;
import java.util.List;

import static com.intel.bkp.utils.ByteConverter.toBytes;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class ProvVerifyEncComponentTest {

    private static final byte[] MAC_KEY = new byte[32];
    private static final byte[] SEK_KEY = new byte[32];
    private static final byte[] IV = new byte[12];
    @Mock
    private ProvisioningTransferObject transferObject;

    @Mock
    private ProvisioningRequestDTOReader dtoReader;

    @Mock
    private ProvisioningHandler successor;

    @Mock
    private ProvContextEnc context;

    @Mock
    private CommandLayer commandLayer;

    @InjectMocks
    private ProvVerifyEncComponent sut;

    @BeforeEach
    void setUp() throws Exception {
        sut.setSuccessor(successor);
        when(transferObject.getDtoReader()).thenReturn(dtoReader);
        when(dtoReader.getFlowStage()).thenReturn(FlowStage.SIGMA_ENC);
        when(dtoReader.read(any())).thenReturn(context);

        when(context.getSessionMacKey()).thenReturn(MAC_KEY);
        when(context.getMessageResponseCounter()).thenReturn(0);
        when(context.getSigmaEncIv()).thenReturn(new byte[12]);
        when(context.getSessionEncryptionKey()).thenReturn(SEK_KEY);
    }

    @Test
    void handle_WithNotSupportedFlowStage_VerifySuccessorCalled() {
        // given
        when(dtoReader.getFlowStage()).thenReturn(FlowStage.PROV_RESULT);

        // when
        sut.handle(transferObject);

        // then
        ProvHandlerTestUtil.verifySuccessorCalled(successor, transferObject);
    }

    @Test
    void handle_NoEncryptedResponse_Success() {
        // given
        final byte[] sigmaEncResponse = prepareEmptySigmaEncResponse();
        mockCommandLayer(sigmaEncResponse);

        // when
        assertDoesNotThrow(() -> sut.handle(transferObject));
    }

    @Test
    void handle_WithEncryptedResponse_Success() throws Exception {
        // given
        final byte[] sigmaEncResponse = prepareSigmaEncResponse();
        mockCommandLayer(sigmaEncResponse);

        // when
        assertDoesNotThrow(() -> sut.handle(transferObject));
    }

    @Test
    void handle_EncAssetFlowStage_Success() throws Exception {
        // given
        final byte[] sigmaEncResponse = prepareSigmaEncResponse();
        when(dtoReader.getFlowStage()).thenReturn(FlowStage.SIGMA_ENC_ASSET);
        mockCommandLayer(sigmaEncResponse);

        // when
        assertDoesNotThrow(() -> sut.handle(transferObject));
    }

    @Test
    void handle_WithNoValidResponses_ThrowsExceptionFromValidateAndParseResponses() {
        // given
        when(dtoReader.getJtagResponses()).thenReturn(new ArrayList<>());

        // when-then
        ProvHandlerTestUtil.runAndVerifyException(sut, transferObject, ProvisioningGenericException.class);
    }

    @Test
    void handle_WithNoValidResponses_ThrowsExceptionFromRecoverProvisioningContext() throws Exception {
        // given
        when(dtoReader.getFlowStage()).thenReturn(FlowStage.SIGMA_ENC_ASSET);
        when(dtoReader.read(ProvContextEnc.class)).thenThrow(ProvisioningConverterException.class);

        // when-then
        ProvHandlerTestUtil.runAndVerifyException(sut, transferObject, ProvisioningGenericException.class);
    }

    private byte[] prepareEmptySigmaEncResponse() {
        return new SigmaEncResponseBuilder().build().array();
    }

    private byte[] prepareSigmaEncResponse() throws Exception {
        SigmaEncResponseBuilder builder = new SigmaEncResponseBuilder();

        AesCtrSigmaEncProviderImpl encryptionProvider =
            new AesCtrSigmaEncProviderImpl(SEK_KEY, new SecureSessionIvProvider(new IMessageResponseCounterProvider() {
                @Override
                public byte[] getInitialIv() {
                    return IV;
                }

                @Override
                public byte[] getMessageResponseCounter() {
                    return toBytes(1);
                }
            }));

        builder.withActor(EndiannessActor.FIRMWARE);
        byte[] encryptedPayload = EncryptedPayload.from(new SigmaTeardownMessageBuilder().build().array()).build();
        builder.setEncryptedPayload(encryptionProvider.encrypt(encryptedPayload));
        builder.setPayloadLen(encryptedPayload.length);
        builder.setFlowType(SigmaEncFlowType.WITH_ENCRYPTED_RESPONSE);
        builder.setMessageResponseCounter(toBytes(1));
        builder.setMac(new HMacSigmaEncProviderImpl(MAC_KEY).getHash(builder.getDataToMac()));

        return builder.build().array();
    }

    private void mockCommandLayer(byte[] sigmaEncResponse) {
        List<ProgrammerResponse> programmerResponses = new ArrayList<>(List.of(
            new ProgrammerResponse(sigmaEncResponse, ResponseStatus.ST_OK)));
        when(dtoReader.getJtagResponses()).thenReturn(programmerResponses);
        when(commandLayer.retrieve(sigmaEncResponse, CommandIdentifier.SIGMA_ENC)).thenReturn(sigmaEncResponse);
    }
}
