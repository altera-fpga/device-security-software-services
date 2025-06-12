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

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmContextProviderImpl;
import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.common.service.GetAttestationCertificateMessageSender;
import com.intel.bkp.bkps.protocol.common.service.GetChipIdMessageSender;
import com.intel.bkp.bkps.protocol.common.service.SigmaTeardownMessageSender;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTOBuilder;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class ProvSigmaCreateComponent extends ProvisioningHandler {

    private final GetChipIdMessageSender getChipIdMessageSender;
    private final SigmaTeardownMessageSender sigmaTeardownMessageSender;
    private final GetAttestationCertificateMessageSender getAttestationCertificateMessageSender;
    private final AesGcmContextProviderImpl contextEncryptionProvider;

    @Override
    public ProvisioningResponseDTO handle(ProvisioningTransferObject transferObject) {
        final ProvisioningRequestDTOReader dtoReader = transferObject.getDtoReader();
        final FlowStage flowStage = dtoReader.getFlowStage();

        if (FlowStage.PROTOCOL_DECISION.equals(flowStage)) {
            return perform(transferObject);
        }

        return successor.handle(transferObject);
    }

    private ProvisioningResponseDTO perform(ProvisioningTransferObject transferObject) {
        log.info(prepareLogEntry("create SIGMA session."));

        final List<ProgrammerMessage> programmerMessages = new ArrayList<>();
        programmerMessages.add(getChipIdMessageSender.create());
        programmerMessages.add(sigmaTeardownMessageSender.create());
        programmerMessages.add(getAttestationCertificateMessageSender.create());

        try {
            return new ProvisioningResponseDTOBuilder()
                .withMessages(programmerMessages)
                .flowStage(FlowStage.SIGMA_CREATE_SESSION)
                .protocolType(transferObject.getProtocolType())
                .encryptionProvider(contextEncryptionProvider)
                .build();
        } catch (ProvisioningConverterException | EncryptionProviderException e) {
            throw new ProvisioningGenericException(e);
        }
    }
}
