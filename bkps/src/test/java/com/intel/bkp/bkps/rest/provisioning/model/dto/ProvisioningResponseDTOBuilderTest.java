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

import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.common.model.ProtocolType;
import com.intel.bkp.crypto.aesgcm.AesGcmProvider;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class ProvisioningResponseDTOBuilderTest {

    private static final String JSON_CONTEXT = "{\"flowStage\":\"SPDM_GET_CHIPID\",\"protocolType\":\"SPDM\","
        + "\"contextData\":null}";

    @Mock
    private List<ProgrammerMessage> programmerMessages;

    @Mock
    private AesGcmProvider encryptionProvider;

    @Test
    void build_WithNoProvider_ThrowsException() {
        //given
        ProvisioningResponseDTOBuilder sut = basicBuilder()
            .withMessages(programmerMessages);

        // when-then
        assertThrows(EncryptionProviderException.class, sut::build);
    }

    @Test
    void build_Success() throws Exception {
        //given
        when(encryptionProvider.encrypt(JSON_CONTEXT.getBytes())).thenReturn(new byte[]{1, 2, 3});
        ProvisioningResponseDTOBuilder sut = basicBuilder()
            .withMessages(programmerMessages)
            .encryptionProvider(encryptionProvider);

        // when
        ProvisioningResponseDTO result = sut.build();

        //then
        assertNotNull(result);
    }

    @Test
    void done_WithNoJtagCommands_ReturnEmpty() {
        //given
        ProvisioningResponseDTOBuilder sut = basicBuilder()
            .encryptionProvider(encryptionProvider);

        // when
        ProvisioningResponseDTO result = sut.done();

        //then
        assertTrue(result.getJtagCommands().isEmpty());
    }

    @Test
    void done_WithJtagCommands_ReturnNotEmpty() {
        //given
        final ArrayList<ProgrammerMessage> list = new ArrayList<>();
        list.add(new ProgrammerMessage(1, "test".getBytes()));
        ProvisioningResponseDTOBuilder sut = basicBuilder()
            .withMessages(list)
            .encryptionProvider(encryptionProvider);

        // when
        ProvisioningResponseDTO result = sut.done();

        //then
        assertFalse(result.getJtagCommands().isEmpty());
    }

    private ProvisioningResponseDTOBuilder basicBuilder() {
        return new ProvisioningResponseDTOBuilder()
            .flowStage(FlowStage.SPDM_GET_CHIPID)
            .protocolType(ProtocolType.SPDM);
    }
}

