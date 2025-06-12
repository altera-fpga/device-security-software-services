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

import com.intel.bkp.bkps.exception.ProgrammerResponseNumberException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.utils.ProgrammerResponseToDataAdapter;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.command.logger.CommandLogger;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.command.responses.sigma.SigmaM3Response;
import com.intel.bkp.command.responses.sigma.SigmaM3ResponseBuilder;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

import static com.intel.bkp.bkps.programmer.utils.ProgrammerResponsesNumberVerifier.verifyNumberOfResponses;
import static com.intel.bkp.command.logger.CommandLoggerValues.PSGSIGMA_M3_RESPONSE;

@Component
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class ProvVerifyM3Component extends ProvisioningHandler {

    private static final int EXPECTED_NUMBER_OF_RESPONSES = 1;

    private final CommandLayer commandLayer;

    @Override
    public ProvisioningResponseDTO handle(ProvisioningTransferObject transferObject) {
        final ProvisioningRequestDTOReader dtoReader = transferObject.getDtoReader();
        if (FlowStage.SIGMA_AUTH_DATA.equals(dtoReader.getFlowStage())) {
            perform(dtoReader.getJtagResponses());
        }
        return successor.handle(transferObject);
    }

    private void perform(List<ProgrammerResponse> responses) {
        verifyResponses(responses);
        final ProgrammerResponseToDataAdapter adapter = new ProgrammerResponseToDataAdapter(responses);
        verifySigmaS3Response(adapter);
    }

    private void verifyResponses(List<ProgrammerResponse> responses) {
        try {
            verifyNumberOfResponses(responses, EXPECTED_NUMBER_OF_RESPONSES);
        } catch (ProgrammerResponseNumberException e) {
            throw new ProvisioningGenericException(e.getMessage());
        }
    }

    private void verifySigmaS3Response(ProgrammerResponseToDataAdapter adapter) {
        final SigmaM3Response sigmaM3Response = new SigmaM3ResponseBuilder()
            .parse(retrieveM3(adapter))
            .build();
        CommandLogger.log(sigmaM3Response, PSGSIGMA_M3_RESPONSE, this.getClass());
    }

    private byte[] retrieveM3(ProgrammerResponseToDataAdapter adapter) {
        return commandLayer.retrieve(adapter.getNext(), CommandIdentifier.SIGMA_M3);
    }
}
