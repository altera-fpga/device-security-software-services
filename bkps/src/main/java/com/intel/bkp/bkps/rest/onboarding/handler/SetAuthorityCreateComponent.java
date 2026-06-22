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
import com.intel.bkp.bkps.exception.SetAuthorityGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.common.service.GetAttestationCertificateMessageSender;
import com.intel.bkp.bkps.protocol.common.service.GetChipIdMessageSender;
import com.intel.bkp.bkps.protocol.common.service.GetIdCodeMessageSender;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityContext;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityRequestDTOReader;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityResponseDTOBuilder;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityTransferObject;
import com.intel.bkp.bkps.rest.onboarding.model.SpdmMessageDTO;
import com.intel.bkp.bkps.spdm.model.UnrecoverableMessageFromQueueEmpty;
import com.intel.bkp.bkps.spdm.service.SpdmBackgroundService;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import dev.failsafe.Failsafe;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static com.intel.bkp.bkps.programmer.model.MessageType.SEND_PACKET;

@Component
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class SetAuthorityCreateComponent extends SetAuthorityHandler {

    private final GetChipIdMessageSender getChipIdMessageSender;
    private final GetIdCodeMessageSender getIdCodeMessageSender;
    private final GetAttestationCertificateMessageSender getAttestationCertificateMessageSender;
    private final SpdmBackgroundService spdmBackgroundService;
    private final AesGcmContextProviderImpl contextEncryptionProvider;

    @Override
    public SetAuthorityResponseDTO handle(SetAuthorityTransferObject transferObject) {
        final SetAuthorityContext context = transferObject.getDtoReader().getContext();
        if (context.getFlowStage() == FlowStage.SET_AUTHORITY_PACK) {
            return perform(transferObject);
        }
        return successor.handle(transferObject);
    }

    private SetAuthorityResponseDTO perform(SetAuthorityTransferObject transferObject) {
        log.info(prepareLogEntry("create session."));

        Failsafe.with(retryPolicy).run(spdmBackgroundService::ensureProcessIsNotRunning);

        spdmBackgroundService.startGetVersion();

        final List<ProgrammerMessage> programmerMessages = new ArrayList<>();

        programmerMessages.add(getChipIdMessageSender.create());
        programmerMessages.add(getIdCodeMessageSender.create());
        programmerMessages.add(getAttestationCertificateMessageSender.create());

        try {
            final SpdmMessageDTO messageFromQueue = spdmBackgroundService.getMessageFromQueue();

            programmerMessages.add(ProgrammerMessage.from(SEND_PACKET, messageFromQueue.getMessage()));
            final SetAuthorityRequestDTO dto = transferObject.getDto();
            final SetAuthorityRequestDTOReader dtoReader = transferObject.getDtoReader();
            final SetAuthorityContext context = dtoReader.getContext();
            context.setPufType(PufType.fromOrdinal(dto.getPufType()));
            context.setSlotId(dto.getSlotId());
            context.setForceEnrollment(dto.isForceEnrollment());
            context.setFlowStage(FlowStage.SET_AUTHORITY_SESSION);
            return new SetAuthorityResponseDTOBuilder()
                .context(context)
                .withMessages(programmerMessages)
                .encryptionProvider(contextEncryptionProvider)
                .build();
        } catch (EncryptionProviderException | IOException e) {
            throw new SetAuthorityGenericException("Preparing response failed.", e);
        } catch (UnrecoverableMessageFromQueueEmpty e) {
            throw new SetAuthorityGenericException("No response from SPDM Service.");
        }
    }
}
