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

package com.intel.bkp.bkps.protocol.spdm.handler;

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmContextProviderImpl;
import com.intel.bkp.bkps.exception.ProgrammerResponseNumberException;
import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.utils.ProgrammerResponseToDataAdapter;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.common.model.ProvContext;
import com.intel.bkp.bkps.protocol.spdm.model.ProvSpdmContext;
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

import static com.intel.bkp.bkps.programmer.model.MessageType.SEND_PACKET;
import static com.intel.bkp.bkps.programmer.utils.ProgrammerResponsesNumberVerifier.verifyNumberOfResponses;

@Component
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class ProvSpdmCommunicationComponent extends ProvisioningHandler {

    private static final int EXPECTED_NUMBER_OF_RESPONSES = 1;

    private final SpdmBackgroundService spdmBackgroundService;
    private final AesGcmContextProviderImpl contextEncryptionProvider;

    @Override
    public ProvisioningResponseDTO handle(ProvisioningTransferObject transferObject) {
        final ProvisioningRequestDTOReader dtoReader = transferObject.getDtoReader();
        final FlowStage flowStage = dtoReader.getFlowStage();
        if (FlowStage.SPDM_SESSION.equals(flowStage)) {
            return perform(dtoReader, transferObject);
        }

        return successor.handle(transferObject);
    }

    private ProvisioningResponseDTO perform(ProvisioningRequestDTOReader dtoReader,
                                            ProvisioningTransferObject transferObject) {
        log.info(prepareLogEntry("SPDM communication."));

        if (!spdmBackgroundService.isProcessing()) {
            throw new ProvisioningGenericException("SPDM Service is not working.");
        }

        final ProvSpdmContext context = recoverProvisioningContext(dtoReader);

        log.info(prepareLogEntry("parsing quartus responses..."));

        final List<ProgrammerResponse> jtagResponses = dtoReader.getJtagResponses();

        try {
            verifyNumberOfResponses(jtagResponses, EXPECTED_NUMBER_OF_RESPONSES);
        } catch (ProgrammerResponseNumberException e) {
            throw new ProvisioningGenericException(e.getMessage());
        }

        final var adapter = new ProgrammerResponseToDataAdapter(jtagResponses);

        spdmBackgroundService.pushResponseToQueue(new SpdmMessageDTO(adapter.getNext()));

        try {
            return spdmBackgroundService.tryGetMessageFromQueue()
                .map(messageDTO -> buildResponse(messageDTO, context, transferObject))
                .orElseGet(() -> passToSuccessor(transferObject));
        } catch (MessageFromQueueEmpty e) {
            throw new ProvisioningGenericException("SPDM Service failed to complete gracefully.");
        }
    }

    private ProvisioningResponseDTO buildResponse(SpdmMessageDTO spdmMessageDTO, ProvContext context,
                                                  ProvisioningTransferObject transferObject) {
        try {
            return new ProvisioningResponseDTOBuilder()
                .context(context)
                .withMessages(List.of(ProgrammerMessage.from(SEND_PACKET, spdmMessageDTO.getMessage())))
                .flowStage(FlowStage.SPDM_SESSION)
                .protocolType(transferObject.getProtocolType())
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

        if (!processResult.isSuccess()) {
            throw new ProvisioningGenericException("SPDM Process failed with status: %s".formatted(processResult));
        }

        return successor.handle(transferObject);
    }

    private ProvSpdmContext recoverProvisioningContext(ProvisioningRequestDTOReader requestDTOReader) {
        try {
            return (ProvSpdmContext) requestDTOReader.read(ProvSpdmContext.class);
        } catch (ProvisioningConverterException e) {
            throw new ProvisioningGenericException(e);
        }
    }

}
