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

package com.intel.bkp.bkps.rest.onboarding.handler;

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmContextProviderImpl;
import com.intel.bkp.bkps.exception.ProgrammerResponseNumberException;
import com.intel.bkp.bkps.exception.SetAuthorityGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.utils.ProgrammerResponseToDataAdapter;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityContext;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityRequestDTOReader;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityResponseDTOBuilder;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityTransferObject;
import com.intel.bkp.bkps.rest.onboarding.model.SpdmMessageDTO;
import com.intel.bkp.bkps.spdm.model.MessageFromQueueEmpty;
import com.intel.bkp.bkps.spdm.model.SpdmThreadError;
import com.intel.bkp.bkps.spdm.service.SpdmBackgroundService;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;

import static com.intel.bkp.bkps.programmer.model.MessageType.SEND_PACKET;
import static com.intel.bkp.bkps.programmer.utils.ProgrammerResponsesNumberVerifier.verifyNumberOfResponses;

@Component
@Slf4j
@RequiredArgsConstructor
public class SetAuthorityProtocolCommunicationComponent extends SetAuthorityHandler {

    private static final int EXPECTED_NUMBER_OF_RESPONSES = 1;
    private final SpdmBackgroundService spdmBackgroundService;
    private final AesGcmContextProviderImpl contextEncryptionProvider;

    @Override
    public SetAuthorityResponseDTO handle(SetAuthorityTransferObject transferObject) {
        final SetAuthorityContext context = transferObject.getDtoReader().getContext();
        if (context.getFlowStage() == FlowStage.SET_AUTHORITY_CERTCHAIN) {
            return perform(transferObject);
        }
        return successor.handle(transferObject);
    }

    private SetAuthorityResponseDTO perform(SetAuthorityTransferObject transferObject) {
        if (!spdmBackgroundService.isProcessing()) {
            throw new SetAuthorityGenericException("SPDM Service is not working.");
        }

        final SetAuthorityRequestDTOReader dtoReader = transferObject.getDtoReader();
        final SetAuthorityContext context = dtoReader.getContext();

        log.info(prepareLogEntry("parsing quartus responses..."));

        final List<ProgrammerResponse> jtagResponses = dtoReader.getJtagResponses();

        try {
            verifyNumberOfResponses(jtagResponses, EXPECTED_NUMBER_OF_RESPONSES);
        } catch (ProgrammerResponseNumberException e) {
            throw new SetAuthorityGenericException(e.getMessage());
        }

        final var adapter = new ProgrammerResponseToDataAdapter(jtagResponses);

        spdmBackgroundService.pushResponseToQueue(new SpdmMessageDTO(adapter.getNext()));

        try {
            return spdmBackgroundService.tryGetMessageFromQueue()
                .map(messageDTO -> buildResponse(messageDTO, context))
                .orElseGet(() -> passToSuccessor(transferObject));
        } catch (MessageFromQueueEmpty e) {
            throw new SetAuthorityGenericException("SPDM Service failed to complete gracefully.");
        }
    }

    private SetAuthorityResponseDTO buildResponse(SpdmMessageDTO spdmMessageDTO, SetAuthorityContext context) {
        try {
            return new SetAuthorityResponseDTOBuilder()
                .context(context)
                .withMessages(List.of(ProgrammerMessage.from(SEND_PACKET, spdmMessageDTO.getMessage())))
                .encryptionProvider(contextEncryptionProvider)
                .build();
        } catch (EncryptionProviderException | IOException e) {
            throw new SetAuthorityGenericException("Preparing response failed.", e);
        }
    }

    private SetAuthorityResponseDTO passToSuccessor(SetAuthorityTransferObject transferObject) {
        final SpdmThreadError processResult = spdmBackgroundService.getProcessResult()
            .orElse(SpdmThreadError.FAILURE);

        log.debug("SPDM Service - process result: {}", processResult);

        if (!processResult.isSuccess()) {
            throw new SetAuthorityGenericException("SPDM Process failed with status: %s".formatted(processResult));
        }

        return successor.handle(transferObject);
    }
}
