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

package com.intel.bkp.bkps.protocol.common.handler;

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmContextProviderImpl;
import com.intel.bkp.bkps.exception.ProgrammerResponseNumberException;
import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.utils.ProgrammerResponseToDataAdapter;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.common.model.ProtocolType;
import com.intel.bkp.bkps.rest.onboarding.model.SpdmMessageDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTOBuilder;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.bkps.spdm.model.MessageFromQueueEmpty;
import com.intel.bkp.bkps.spdm.model.SpdmThreadError;
import com.intel.bkp.bkps.spdm.service.SpdmBackgroundService;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

import static com.intel.bkp.bkps.programmer.model.MessageType.SEND_PACKET;
import static com.intel.bkp.bkps.programmer.utils.ProgrammerResponsesNumberVerifier.verifyNumberOfResponses;

@Component
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class ProvDecisionComponent extends ProvisioningHandler {

    private static final int EXPECTED_NUMBER_OF_RESPONSES = 1;

    private final SpdmBackgroundService spdmBackgroundService;
    private final AesGcmContextProviderImpl contextEncryptionProvider;

    private final ProvProtocolChooserService provProtocolChooserService;

    @Override
    public ProvisioningResponseDTO handle(ProvisioningTransferObject transferObject) {
        final ProvisioningRequestDTOReader dtoReader = transferObject.getDtoReader();
        final FlowStage flowStage = dtoReader.getFlowStage();

        return Optional.ofNullable(transferObject.getProtocolType())
            .map(protocolType -> runProtocol(protocolType, transferObject))
            .orElseGet(() -> determineProtocol(transferObject, flowStage, dtoReader));
    }

    private ProvisioningResponseDTO determineProtocol(ProvisioningTransferObject transferObject,
                                                      FlowStage flowStage,
                                                      ProvisioningRequestDTOReader dtoReader) {
        if (!FlowStage.PROTOCOL_DECISION.equals(flowStage)) {
            throw new ProvisioningGenericException("ProtocolType could not be determined.");
        }

        try {
            processResponses(dtoReader);
        } catch (ProgrammerResponseNumberException e) {
            throw new ProvisioningGenericException(e.getMessage());
        }

        try {
            return spdmBackgroundService.tryGetMessageFromQueue()
                .map(this::buildResponse)
                .orElseGet(() -> passToSuccessor(transferObject));
        } catch (MessageFromQueueEmpty e) {
            throw new ProvisioningGenericException("SPDM Service failed to complete gracefully.");
        }
    }

    private void processResponses(ProvisioningRequestDTOReader dtoReader) throws ProgrammerResponseNumberException {
        log.info(prepareLogEntry("parsing quartus responses..."));
        final List<ProgrammerResponse> jtagResponses = dtoReader.getJtagResponses();
        verifyNumberOfResponses(jtagResponses, EXPECTED_NUMBER_OF_RESPONSES);

        final var adapter = new ProgrammerResponseToDataAdapter(jtagResponses);

        if (!spdmBackgroundService.isProcessing()) {
            throw new ProvisioningGenericException("SPDM Service is not working.");
        }

        spdmBackgroundService.pushResponseToQueue(new SpdmMessageDTO(adapter.getNext()));
    }

    private ProvisioningResponseDTO buildResponse(SpdmMessageDTO spdmMessageDTO) {
        try {
            return new ProvisioningResponseDTOBuilder()
                .withMessages(List.of(ProgrammerMessage.from(SEND_PACKET, spdmMessageDTO.getMessage())))
                .flowStage(FlowStage.PROTOCOL_DECISION)
                .encryptionProvider(contextEncryptionProvider)
                .build();
        } catch (EncryptionProviderException e) {
            throw new ProvisioningGenericException("Preparing response failed.", e);
        } catch (ProvisioningConverterException e) {
            throw new ProvisioningGenericException(e);
        }
    }

    private ProvisioningResponseDTO passToSuccessor(ProvisioningTransferObject transferObject) {
        final SpdmThreadError processResult = spdmBackgroundService.getProcessResult()
            .orElse(SpdmThreadError.FAILURE);

        log.debug("SPDM Service - process result: {}", processResult);

        if (processResult.isSuccess()) {
            log.debug("SPDM VCA returned success.");
            return runProtocol(ProtocolType.SPDM, transferObject);
        } else {
            log.debug("SPDM VCA failed.");
            return runProtocol(ProtocolType.SIGMA, transferObject);
        }
    }

    private ProvisioningResponseDTO runProtocol(ProtocolType protocolType, ProvisioningTransferObject transferObject) {
        log.debug("Choosing protocol service by protocol type: {}", protocolType);
        transferObject.setProtocolType(protocolType);
        return switch (protocolType) {
            case SPDM -> provProtocolChooserService.runSpdm(transferObject);
            case SIGMA -> provProtocolChooserService.runSigma(transferObject);
        };
    }
}
