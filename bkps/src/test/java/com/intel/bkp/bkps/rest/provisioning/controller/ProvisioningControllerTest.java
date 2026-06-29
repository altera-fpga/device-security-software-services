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

package com.intel.bkp.bkps.rest.provisioning.controller;

import com.intel.bkp.bkps.exception.CommandNotSupportedException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.rest.RestUtil;
import com.intel.bkp.bkps.rest.provisioning.ProvisioningResource;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ContextDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTO;
import com.intel.bkp.bkps.rest.provisioning.service.ProvisioningService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
public class ProvisioningControllerTest {

    private static final RuntimeException RUNTIME_EXCEPTION = new RuntimeException("RUNTIME_EXCEPTION");
    private static final ProvisioningGenericException PROV_EXCEPTION =
        new ProvisioningGenericException("PROV_EXCEPTION");
    private static final CommandNotSupportedException CMD_NOT_SUPPORTED_EXCEPTION = new CommandNotSupportedException();

    @Mock
    private ProvisioningService provisioningService;

    @InjectMocks
    private ProvisioningController provisioningController;

    private MockMvc mockMvc;

    private final ProvisioningRequestDTO provisioningRequestDto = getProvisioningRequestDto();

    @BeforeEach
    void setup() {
        this.mockMvc = MockMvcBuilders.standaloneSetup(provisioningController).build();
    }

    @Test
    void provisioning_getNext_Success() throws Exception {
        // when
        performProvisioningMvc()
            .andExpect(status().isOk());

        // then
        verify(provisioningService).getNext(any(ProvisioningRequestDTO.class));
    }

    @Test
    void provisioning_getNext_ThrowsException_RethrowsProvisioningGenericException() {
        // given
        mockProvisioningServiceThrow(RUNTIME_EXCEPTION);

        // when-then
        assertThrows(ProvisioningGenericException.class, this::performProvisioningDirect);
    }

    @Test
    void provisioning_getNext_ThrowsCommandNotSupportedException_Rethrows() {
        // given
        mockProvisioningServiceThrow(CMD_NOT_SUPPORTED_EXCEPTION);

        // when-then
        assertThrows(CommandNotSupportedException.class, this::performProvisioningDirect);
    }

    @Test
    void provisioning_getNext_ThrowsProvisioningGenericException_Rethrows() {
        // given
        mockProvisioningServiceThrow(PROV_EXCEPTION);

        // when-then
        assertThrows(ProvisioningGenericException.class, this::performProvisioningDirect);
    }

    private ProvisioningRequestDTO getProvisioningRequestDto() {
        ProvisioningRequestDTO dto = new ProvisioningRequestDTO();

        dto.setContext(new ContextDTO("test"));
        dto.setCfgId(1L);
        dto.setApiVersion(1);
        dto.setSupportedCommands(1);
        dto.setJtagResponses(new ArrayList<>());
        return dto;
    }

    private ResultActions performProvisioningMvc() throws Exception {
        return perform(ProvisioningResource.GET_NEXT, provisioningRequestDto);
    }

    private void performProvisioningDirect() {
        provisioningController.getNext(provisioningRequestDto);
    }

    private ResultActions perform(String node, Object dto) throws Exception {
        return mockMvc.perform(post(ProvisioningResource.PROVISIONING_NODE + node)
            .contentType(RestUtil.APPLICATION_JSON_UTF8)
            .content(RestUtil.convertObjectToJsonBytes(dto)));
    }

    private void mockProvisioningServiceThrow(RuntimeException exception) {
        doThrow(exception).when(provisioningService).getNext(eq(provisioningRequestDto));
    }
}
