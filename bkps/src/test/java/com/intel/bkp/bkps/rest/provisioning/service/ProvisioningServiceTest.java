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


package com.intel.bkp.bkps.rest.provisioning.service;

import com.intel.bkp.bkps.protocol.common.handler.ProvAdapterComponent;
import com.intel.bkp.bkps.protocol.common.handler.ProvCreateComponent;
import com.intel.bkp.bkps.protocol.common.handler.ProvDecisionComponent;
import com.intel.bkp.bkps.protocol.common.handler.ProvQuartusStatusVerifierComponent;
import com.intel.bkp.bkps.protocol.common.handler.ProvSupportedCommandsComponent;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class ProvisioningServiceTest {

    private static final int API_VERSION = 1;

    @Mock
    private ProvisioningHandler provEntrypointComponent;

    @Mock
    private ProvSupportedCommandsComponent provSupportedCommandsComponent;

    @Mock
    private ProvCreateComponent provCreateComponent;

    @Mock
    private ProvAdapterComponent provAdapterComponent;

    @Mock
    private ProvQuartusStatusVerifierComponent provQuartusStatusVerifierComponent;

    @Mock
    private ProvDecisionComponent provDecisionComponent;

    @Mock
    private ProvisioningRequestDTO dto;

    @Mock
    private ProvisioningResponseDTO responseDTO;

    @InjectMocks
    private ProvisioningService sut;

    @BeforeEach
    void setUp() {
        when(dto.getApiVersion()).thenReturn(API_VERSION);
        when(provEntrypointComponent.handle(any(ProvisioningTransferObject.class))).thenReturn(responseDTO);
        sut.setProvEntrypointComponent(provEntrypointComponent);
    }

    @Test
    void getNext_VerifyApiVersion() {
        // when
        ProvisioningResponseDTO result = sut.getNext(dto);

        // then
        verify(responseDTO).setApiVersion(API_VERSION);
    }

    @Test
    void getNext_VerifyCallHandle() {
        // when
        sut.getNext(dto);

        // then
        verify(provEntrypointComponent).handle(any(ProvisioningTransferObject.class));
    }

    @Test
    void getNext_VerifySuccessors() {
        // when
        sut.init();

        // then
        verify(provEntrypointComponent).setSuccessor(provSupportedCommandsComponent);
        verify(provSupportedCommandsComponent).setSuccessor(provCreateComponent);
        verify(provCreateComponent).setSuccessor(provAdapterComponent);
        verify(provAdapterComponent).setSuccessor(provQuartusStatusVerifierComponent);
        verify(provQuartusStatusVerifierComponent).setSuccessor(provDecisionComponent);
    }
}
