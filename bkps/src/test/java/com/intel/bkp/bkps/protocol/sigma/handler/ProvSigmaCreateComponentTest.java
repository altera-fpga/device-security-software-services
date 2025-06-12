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
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.CommunicationStatus;
import com.intel.bkp.bkps.programmer.model.MessageType;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.protocol.common.handler.ProvHandlerTestUtil;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.common.service.GetAttestationCertificateMessageSender;
import com.intel.bkp.bkps.protocol.common.service.GetChipIdMessageSender;
import com.intel.bkp.bkps.protocol.common.service.SigmaTeardownMessageSender;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class ProvSigmaCreateComponentTest {

    private static final byte[] SIGMA_TEARDOWN = new byte[]{1, 2};
    private static final byte[] GET_CHIPID = new byte[]{3, 4};
    private static final byte[] GET_ATTESTATION_CERTIFICATE = new byte[]{5, 6};

    @Mock
    private ProvisioningTransferObject transferObject;

    @Mock
    private ProvisioningRequestDTOReader dtoReader;

    @Mock
    private ProvisioningHandler successor;

    @Mock
    private GetChipIdMessageSender getChipIdMessageSender;

    @Mock
    private SigmaTeardownMessageSender sigmaTeardownMessageSender;

    @Mock
    private GetAttestationCertificateMessageSender getAttestationCertificateMessageSender;

    @Mock
    private AesGcmContextProviderImpl contextEncryptionProvider;

    @InjectMocks
    private ProvSigmaCreateComponent sut;

    @BeforeEach
    void setUp() {
        sut.setSuccessor(successor);
        when(transferObject.getDtoReader()).thenReturn(dtoReader);
    }

    @Test
    void handle_FlowStageDecision_CallsPerform() {
        // given
        when(dtoReader.getFlowStage()).thenReturn(FlowStage.PROTOCOL_DECISION);

        final int expectedNoOfCommands = 3;
        prepareCommands();
        mockContextEncrypt();

        // when
        ProvisioningResponseDTO result = sut.handle(transferObject);

        // then
        assertNotNull(result.getContext());
        assertNotNull(result.getJtagCommands());
        assertEquals(expectedNoOfCommands, result.getJtagCommands().size());
        assertEquals(CommunicationStatus.CONTINUE.getStatus(), result.getStatus());
    }

    @Test
    void handle_FlowStageNotDecision_CallSuccessor() {
        // given
        when(dtoReader.getFlowStage()).thenReturn(FlowStage.SIGMA_CREATE_SESSION);

        // when
        sut.handle(transferObject);

        // then
        ProvHandlerTestUtil.verifySuccessorCalled(successor, transferObject);
    }

    @Test
    void handle_EncryptionProviderThrows() {
        // given
        when(dtoReader.getFlowStage()).thenReturn(FlowStage.PROTOCOL_DECISION);
        prepareCommands();
        mockContextEncryptThrows();

        // when-then
        ProvHandlerTestUtil.runAndVerifyException(sut, transferObject, ProvisioningGenericException.class);
    }

    private void prepareCommands() {
        when(getChipIdMessageSender.create()).thenReturn(getFrom(GET_CHIPID));
        when(sigmaTeardownMessageSender.create()).thenReturn(getFrom(SIGMA_TEARDOWN));
        when(getAttestationCertificateMessageSender.create()).thenReturn(getFrom(GET_ATTESTATION_CERTIFICATE));
    }

    private static ProgrammerMessage getFrom(byte[] bytes) {
        return ProgrammerMessage.from(MessageType.SEND_PACKET, bytes);
    }

    @SneakyThrows
    private void mockContextEncrypt() {
        when(contextEncryptionProvider.encrypt(any())).thenReturn(new byte[]{1, 2, 3});
    }

    @SneakyThrows
    private void mockContextEncryptThrows() {
        when(contextEncryptionProvider.encrypt(any())).thenThrow(new EncryptionProviderException("test"));
    }
}
