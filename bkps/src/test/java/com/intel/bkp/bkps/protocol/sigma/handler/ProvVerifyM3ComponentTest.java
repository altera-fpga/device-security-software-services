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

import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.model.ResponseStatus;
import com.intel.bkp.bkps.protocol.common.handler.ProvHandlerTestUtil;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.command.responses.common.GetChipIdResponseBuilder;
import com.intel.bkp.command.responses.sigma.SigmaM3ResponseBuilder;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class ProvVerifyM3ComponentTest {

    private static final byte[] SIGMA_M3_RESPONSE = new SigmaM3ResponseBuilder().build().array();
    private static final byte[] GET_CHIPID_RESPONSE = new GetChipIdResponseBuilder().build().array();
    private static final List<ProgrammerResponse> QUARTUS_RESPONSES = new ArrayList<>(List.of(
        new ProgrammerResponse(SIGMA_M3_RESPONSE, ResponseStatus.ST_OK)));
    private static final List<ProgrammerResponse> INVALID_QUARTUS_RESPONSES = new ArrayList<>(List.of(
        new ProgrammerResponse(GET_CHIPID_RESPONSE, ResponseStatus.ST_OK)));

    @Mock
    private ProvisioningTransferObject transferObject;

    @Mock
    private ProvisioningRequestDTOReader dtoReader;

    @Mock
    private ProvisioningHandler successor;

    @Mock
    private CommandLayer commandLayer;

    @InjectMocks
    private ProvVerifyM3Component sut;

    @BeforeEach
    void setUp() {
        sut.setSuccessor(successor);
        when(transferObject.getDtoReader()).thenReturn(dtoReader);
        when(dtoReader.getFlowStage()).thenReturn(FlowStage.SIGMA_AUTH_DATA);
        when(dtoReader.getJtagResponses()).thenReturn(QUARTUS_RESPONSES);
    }

    @Test
    void handle_NotProperFlowStage_CallsSuccessor() {
        // given
        when(dtoReader.getFlowStage()).thenReturn(FlowStage.PROV_RESULT);

        // when
        sut.handle(transferObject);

        // then
        ProvHandlerTestUtil.verifySuccessorCalled(successor, transferObject);
    }

    @Test
    void handle_Success() {
        // given
        when(commandLayer.retrieve(SIGMA_M3_RESPONSE, CommandIdentifier.SIGMA_M3)).thenReturn(SIGMA_M3_RESPONSE);

        // when
        assertDoesNotThrow(() -> sut.handle(transferObject));
    }

    @Test
    void handle_WrongResponse_Throws() {
        // given
        when(dtoReader.getJtagResponses()).thenReturn(INVALID_QUARTUS_RESPONSES);
        when(commandLayer.retrieve(GET_CHIPID_RESPONSE, CommandIdentifier.SIGMA_M3)).thenReturn(GET_CHIPID_RESPONSE);

        // when-then
        assertThrows(ByteBufferSafeException.class,
            () -> sut.handle(transferObject)
        );
    }
}
