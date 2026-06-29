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

package com.intel.bkp.bkps.testutils;

import com.intel.bkp.bkps.programmer.model.CommunicationStatus;
import com.intel.bkp.bkps.programmer.model.dto.ResponseDTO;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ContextDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.bkps.rest.provisioning.service.ServiceConfigurationProvider;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;

import static com.intel.bkp.bkps.rest.provisioning.model.dto.ContextDTO.empty;
import static org.junit.jupiter.api.Assertions.assertEquals;

@AllArgsConstructor
@Slf4j
public class RequestUtils {

    private static final int API_VERSION = 1;
    private static final int SUPPORTED_COMMANDS = 3;

    private final ServiceConfigurationProvider serviceConfigurationProvider;
    private final ProvisioningHandler provisioningHandler;
    private final Long cfgId;

    public ProvisioningResponseDTO performGetNext(int expectedResponses) {
        final ProvisioningRequestDTO requestDTO = getProvisioningRequestDTO();

        final ProvisioningResponseDTO nextResponse = provisioningHandler.handle(buildTransferObject(requestDTO));
        validateResponse(nextResponse, expectedResponses);
        return nextResponse;
    }

    public ProvisioningResponseDTO performGetNext(ProvisioningResponseDTO previousResponse, int expectedResponses,
        ResponseDTO... responseDTOs) {
        final ProvisioningRequestDTO requestDTO =
            getProvisioningRequestDTO(previousResponse, responseDTOs);

        final ProvisioningResponseDTO nextResponse = provisioningHandler.handle(buildTransferObject(requestDTO));
        validateResponse(nextResponse, expectedResponses);
        return nextResponse;
    }

    public void performGetNextDone(ProvisioningResponseDTO previousResponse,
        ResponseDTO... responseDTOs) {
        final ProvisioningRequestDTO requestDTO =
            getProvisioningRequestDTO(previousResponse, responseDTOs);

        final ProvisioningResponseDTO nextResponse = provisioningHandler.handle(buildTransferObject(requestDTO));
        validateResponseDone(nextResponse);
    }

    private ProvisioningTransferObject buildTransferObject(ProvisioningRequestDTO requestDTO) {
        return ProvisioningTransferObject
            .builder()
            .dto(requestDTO)
            .configurationCallback(serviceConfigurationProvider)
            .build();
    }

    private ProvisioningRequestDTO getProvisioningRequestDTO() {
        return getProvisioningRequestDTO(empty());
    }

    private ProvisioningRequestDTO getProvisioningRequestDTO(ContextDTO contextDTO) {
        return getProvisioningRequestDTO(contextDTO, new ArrayList<>());
    }

    private ProvisioningRequestDTO getProvisioningRequestDTO(ContextDTO contextDTO,
        ArrayList<ResponseDTO> jtagResponses) {
        return new ProvisioningRequestDTO(
            contextDTO, cfgId, API_VERSION, SUPPORTED_COMMANDS, jtagResponses
        );
    }

    private ProvisioningRequestDTO getProvisioningRequestDTO(ProvisioningResponseDTO previousResponse,
        ResponseDTO[] responseDTOs) {
        final ArrayList<ResponseDTO> jtagResponses = new ArrayList<>(List.of(responseDTOs));
        return getProvisioningRequestDTO(previousResponse.getContext(), jtagResponses);
    }

    private void validateResponse(ProvisioningResponseDTO response, int jtagSize) {
        assertEquals(CommunicationStatus.CONTINUE.getStatus(), response.getStatus());
        assertEquals(jtagSize, response.getJtagCommands().size());
    }

    private void validateResponseDone(ProvisioningResponseDTO response) {
        assertEquals(CommunicationStatus.DONE.getStatus(), response.getStatus());
        assertEquals(0, response.getJtagCommands().size());
    }
}
