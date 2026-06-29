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

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmContextProviderImpl;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.rest.onboarding.model.SpdmMessageDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.bkps.spdm.model.UnrecoverableMessageFromQueueEmpty;
import com.intel.bkp.bkps.spdm.service.SpdmBackgroundService;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ProvCreateComponentTest {

    private final SpdmMessageDTO messageDTO = new SpdmMessageDTO(new byte[0]);

    @Mock
    private ProvisioningHandler successor;

    @Mock
    private ProvisioningTransferObject transferObject;

    @Mock
    private ProvisioningRequestDTO dto;

    @Mock
    private SpdmBackgroundService spdmBackgroundService;

    @Mock
    private AesGcmContextProviderImpl contextEncryptionProvider;

    @InjectMocks
    private ProvCreateComponent sut;

    @BeforeEach
    void setUp() {
        sut.setSuccessor(successor);
    }

    @SneakyThrows
    @Test
    void handle_ContextEmpty_Perform() {
        // given
        when(transferObject.getDto()).thenReturn(dto);
        when(dto.isContextEmpty()).thenReturn(true);
        when(spdmBackgroundService.getMessageFromQueue()).thenReturn(messageDTO);
        mockContextEncrypt();

        // when
        ProvisioningResponseDTO result = sut.handle(transferObject);

        // then
        verify(spdmBackgroundService).startVcaForProvisioningThread();
        assertNotNull(result);
    }

    @SneakyThrows
    @Test
    void handle_GetMessageThrows() {
        // given
        when(transferObject.getDto()).thenReturn(dto);
        when(dto.isContextEmpty()).thenReturn(true);
        when(spdmBackgroundService.getMessageFromQueue()).thenThrow(new UnrecoverableMessageFromQueueEmpty());

        // when-then
        ProvHandlerTestUtil.runAndVerifyException(sut, transferObject, ProvisioningGenericException.class);
    }

    @SneakyThrows
    @Test
    void handle_ContextNotEmpty_CallsSuccessor() {
        // given
        when(transferObject.getDto()).thenReturn(dto);
        when(dto.isContextEmpty()).thenReturn(false);

        // when
        sut.handle(transferObject);

        // then
        ProvHandlerTestUtil.verifySuccessorCalled(successor, transferObject);
    }

    @SneakyThrows
    private void mockContextEncrypt() {
        when(contextEncryptionProvider.encrypt(any())).thenReturn(new byte[]{1, 2, 3});
    }
}
