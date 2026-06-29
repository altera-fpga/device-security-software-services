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
import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.rest.onboarding.model.SpdmMessageDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTOBuilder;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.bkps.spdm.model.UnrecoverableMessageFromQueueEmpty;
import com.intel.bkp.bkps.spdm.service.SpdmBackgroundService;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import dev.failsafe.Failsafe;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

import static com.intel.bkp.bkps.programmer.model.MessageType.SEND_PACKET;

@Component
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class ProvCreateComponent extends ProvisioningHandler {

    private final SpdmBackgroundService spdmBackgroundService;
    private final AesGcmContextProviderImpl contextEncryptionProvider;

    @Override
    public ProvisioningResponseDTO handle(ProvisioningTransferObject transferObject) {
        if (transferObject.getDto().isContextEmpty()) {
            return perform();
        }

        return successor.handle(transferObject);
    }

    private ProvisioningResponseDTO perform() {
        log.info(prepareLogEntry("create session."));

        Failsafe.with(retryPolicyLong).run(spdmBackgroundService::ensureProcessIsNotRunning);

        spdmBackgroundService.startVcaForProvisioningThread();

        try {
            final SpdmMessageDTO messageFromQueue = spdmBackgroundService.getMessageFromQueue();

            return new ProvisioningResponseDTOBuilder()
                .withMessages(List.of(ProgrammerMessage.from(SEND_PACKET, messageFromQueue.getMessage())))
                .flowStage(FlowStage.PROTOCOL_DECISION)
                .encryptionProvider(contextEncryptionProvider)
                .build();
        } catch (EncryptionProviderException e) {
            throw new ProvisioningGenericException("Preparing response failed.", e);
        } catch (ProvisioningConverterException e) {
            throw new ProvisioningGenericException(e);
        } catch (UnrecoverableMessageFromQueueEmpty e) {
            throw new ProvisioningGenericException("No response from SPDM Service.");
        }
    }
}
