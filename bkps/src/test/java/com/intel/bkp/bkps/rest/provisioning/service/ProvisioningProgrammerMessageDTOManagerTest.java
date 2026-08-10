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

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmContextProviderImpl;
import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.common.model.ProvContextWithFlow;
import com.intel.bkp.bkps.rest.RestUtil;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class ProvisioningProgrammerMessageDTOManagerTest {

    @Mock
    private AesGcmContextProviderImpl contextEncryptionProvider;

    @Mock
    private ProvisioningRequestDTO dto;

    @InjectMocks
    private ProvisioningRequestDTOManager sut;

    @Test
    void getReader_Success() throws Exception {
        // given
        ProvContextWithFlow provContextWithFlow = new ProvContextWithFlow();
        provContextWithFlow.setFlowStage(FlowStage.SIGMA_AUTH_DATA);
        when(contextEncryptionProvider.decrypt(any()))
            .thenReturn(RestUtil.convertObjectToJsonBytes(provContextWithFlow));

        // when
        final ProvisioningRequestDTOReader result = sut.getReader(dto);

        // then
        assertNotNull(result);
    }

    @Test
    void getReader_ThrowsException() throws Exception {
        // given
        byte[] data = new byte[32];
        ThreadLocalRandom.current().nextBytes(data);
        when(contextEncryptionProvider.decrypt(any())).thenReturn(data);

        // when-then
        assertThrows(ProvisioningConverterException.class, () -> sut.getReader(dto));
    }

}
