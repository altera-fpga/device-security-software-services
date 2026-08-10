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

package com.intel.bkp.bkps.rest.onboarding.handler;

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmContextProviderImpl;
import com.intel.bkp.bkps.exception.SetAuthorityGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityContext;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityResponseDTOBuilder;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityTransferObject;
import com.intel.bkp.bkps.rest.onboarding.model.SpdmMessageDTO;
import com.intel.bkp.bkps.spdm.model.UnrecoverableMessageFromQueueEmpty;
import com.intel.bkp.bkps.spdm.service.SpdmBackgroundService;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import dev.failsafe.Failsafe;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static com.intel.bkp.bkps.programmer.model.MessageType.SEND_PACKET;
import static com.intel.bkp.bkps.protocol.common.model.FlowStage.SET_AUTHORITY_DECISION;

@Component
@Slf4j
@RequiredArgsConstructor
public class SetAuthorityProtocolDecisionComponent extends SetAuthorityHandler {

    private final SpdmBackgroundService spdmBackgroundService;
    private final AesGcmContextProviderImpl contextEncryptionProvider;

    @Override
    public SetAuthorityResponseDTO handle(SetAuthorityTransferObject transferObject) {
        if (transferObject.getDto().isContextEmpty()) {
            return perform();
        }
        return successor.handle(transferObject);
    }

    private SetAuthorityResponseDTO perform() {
        Failsafe.with(retryPolicy).run(spdmBackgroundService::ensureProcessIsNotRunning);

        spdmBackgroundService.startVcaForProvisioningThread();

        try {
            final SpdmMessageDTO messageFromQueue = spdmBackgroundService.getMessageFromQueue();

            final List<ProgrammerMessage> programmerMessages = new ArrayList<>();
            programmerMessages.add(ProgrammerMessage.from(SEND_PACKET, messageFromQueue.getMessage()));
            final SetAuthorityContext context = new SetAuthorityContext();
            context.setFlowStage(SET_AUTHORITY_DECISION);
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
