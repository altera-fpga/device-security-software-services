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

import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.model.ResponseStatus;
import com.intel.bkp.bkps.protocol.common.handler.ProvHandlerTestUtil;
import com.intel.bkp.bkps.protocol.common.handler.ProvQuartusStatusVerifierComponent;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class ProvResponseStatusVerifierComponentTest {

    @Mock
    private ProvisioningTransferObject transferObject;

    @Mock
    private ProvisioningRequestDTOReader dtoReader;

    @Mock
    private ProvisioningHandler successor;

    @InjectMocks
    private ProvQuartusStatusVerifierComponent sut;

    private static final List<ProgrammerResponse> QUARTUS_RESPONSES_OK = List.of(
        new ProgrammerResponse(new byte[2], ResponseStatus.ST_OK),
        new ProgrammerResponse(new byte[2], ResponseStatus.ST_OK));

    private static final List<ProgrammerResponse> QUARTUS_RESPONSES_ERROR = List.of(
        new ProgrammerResponse(new byte[2], ResponseStatus.ST_GENERIC_ERROR),
        new ProgrammerResponse(new byte[2], ResponseStatus.ST_OK));

    @BeforeEach
    void setUp() {
        sut.setSuccessor(successor);
        when(transferObject.getDtoReader()).thenReturn(dtoReader);
        when(dtoReader.getJtagResponses()).thenReturn(QUARTUS_RESPONSES_OK);
    }

    @Test
    void handle_AllOk_Success() {
        // when
        sut.handle(transferObject);

        // then
        ProvHandlerTestUtil.verifySuccessorCalled(successor, transferObject);
    }

    @Test
    void handle_Error_ThrowsException() {
        // given
        when(dtoReader.getJtagResponses()).thenReturn(QUARTUS_RESPONSES_ERROR);

        // when-then
        ProvHandlerTestUtil.runAndVerifyException(sut, transferObject, ProvisioningGenericException.class);
    }
}
