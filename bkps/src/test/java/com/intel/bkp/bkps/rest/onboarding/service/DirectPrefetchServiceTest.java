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

package com.intel.bkp.bkps.rest.onboarding.service;

import com.intel.bkp.bkps.programmer.model.CommunicationStatus;
import com.intel.bkp.bkps.rest.onboarding.handler.DirectPrefetchCreateComponent;
import com.intel.bkp.bkps.rest.onboarding.handler.DirectPrefetchDoneComponent;
import com.intel.bkp.bkps.rest.onboarding.handler.DirectPrefetchFetchCertificateComponent;
import com.intel.bkp.bkps.rest.onboarding.handler.DirectPrefetchHandler;
import com.intel.bkp.bkps.rest.onboarding.handler.DirectPrefetchQuartusStatusVerifierComponent;
import com.intel.bkp.bkps.rest.onboarding.handler.DirectPrefetchSupportedCommandsComponent;
import com.intel.bkp.bkps.rest.onboarding.model.DirectPrefetchRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.DirectPrefetchResponseDTO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DirectPrefetchServiceTest {

    @Mock
    private DirectPrefetchHandler prefetchHandler;

    @Mock
    private DirectPrefetchSupportedCommandsComponent prefetchSupportedCommandsComponent;

    @Mock
    private DirectPrefetchCreateComponent prefetchCreateComponent;

    @Mock
    private DirectPrefetchQuartusStatusVerifierComponent prefetchQuartusStatusVerifierComponent;

    @Mock
    private DirectPrefetchFetchCertificateComponent prefetchFetchCertificateComponent;

    @Mock
    private DirectPrefetchDoneComponent prefetchDoneComponent;

    @InjectMocks
    private DirectPrefetchService sut;

    @BeforeEach
    void setUp() {
        sut.setPrefetchEntrypointComponent(prefetchHandler);
        sut.init();
    }

    @Test
    void directPrefetch_WithValidRequest_Success() {
        // given
        final int apiVersionExpected = 1234;
        DirectPrefetchRequestDTO dto = new DirectPrefetchRequestDTO();
        dto.setSupportedCommands(3);
        dto.setApiVersion(apiVersionExpected);
        dto.setJtagResponses(new ArrayList<>());
        when(prefetchHandler.handle(any()))
            .thenReturn(new DirectPrefetchResponseDTO(CommunicationStatus.DONE, new ArrayList<>()));

        // when
        final DirectPrefetchResponseDTO response = sut.perform(dto);

        // then
        assertEquals(CommunicationStatus.DONE.getStatus(), response.getStatus());
        assertEquals(apiVersionExpected, response.getApiVersion());
    }
}
