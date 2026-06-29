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

package com.intel.bkp.bkps.rest.provisioning.model.dto;

import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.common.model.ProvContextWithFlow;
import com.intel.bkp.bkps.rest.RestUtil;
import com.intel.bkp.crypto.aesgcm.AesGcmProvider;
import com.intel.bkp.test.RandomUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class ProvisioningProgrammerMessageDTOReaderTest {

    private static final long CONFIG_ID = 1L;

    @Mock
    AesGcmProvider encryptionProvider;

    @Mock
    ProvisioningRequestDTO dto;

    @Test
    void getContextData_Success() throws Exception {
        // given
        ProvContextWithFlow provContextWithFlow = getProvContextWithFlow();
        byte[] expected = RandomUtils.generateRandomBytes(7);
        provContextWithFlow.setContextData(expected);
        when(encryptionProvider.decrypt(ArgumentMatchers.any()))
            .thenReturn(RestUtil.convertObjectToJsonBytes(provContextWithFlow));

        // when
        ProvisioningRequestDTOReader sut = new ProvisioningRequestDTOReader(encryptionProvider, dto);
        final byte[] actual = sut.getContextData();

        // then
        assertArrayEquals(expected, actual);
    }

    @Test
    void getCfgId_Success() throws Exception {
        // given
        when(encryptionProvider.decrypt(ArgumentMatchers.any()))
            .thenReturn(RestUtil.convertObjectToJsonBytes(getProvContextWithFlow()));
        when(dto.getCfgId()).thenReturn(CONFIG_ID);

        // when
        ProvisioningRequestDTOReader sut = new ProvisioningRequestDTOReader(encryptionProvider, dto);

        // then
        assertEquals(CONFIG_ID, sut.getCfgId());
    }

    @Test
    void init_ThrowsException() throws Exception {
        // given
        byte[] data = RandomUtils.generateRandomBytes(32);
        when(encryptionProvider.decrypt(ArgumentMatchers.any())).thenReturn(data);

        // when-then
        assertThrows(ProvisioningConverterException.class,
            () -> new ProvisioningRequestDTOReader(encryptionProvider, dto));
    }

    private ProvContextWithFlow getProvContextWithFlow() {
        ProvContextWithFlow provContextWithFlow = new ProvContextWithFlow();
        provContextWithFlow.setFlowStage(FlowStage.SIGMA_AUTH_DATA);
        return provContextWithFlow;
    }
}
