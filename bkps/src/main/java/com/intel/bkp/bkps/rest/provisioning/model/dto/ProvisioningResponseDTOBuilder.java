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

package com.intel.bkp.bkps.rest.provisioning.model.dto;

import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.programmer.model.dto.MessageDTO;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.common.model.ProtocolType;
import com.intel.bkp.bkps.protocol.common.model.ProvContext;
import com.intel.bkp.bkps.protocol.common.model.ProvContextWithFlow;
import com.intel.bkp.bkps.rest.provisioning.utils.ProvisioningContextConverter;
import com.intel.bkp.crypto.aesgcm.AesGcmProvider;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import lombok.Getter;

import java.util.List;
import java.util.Optional;

import static com.intel.bkp.bkps.programmer.model.CommunicationStatus.CONTINUE;
import static com.intel.bkp.bkps.programmer.model.CommunicationStatus.DONE;

@Getter
public class ProvisioningResponseDTOBuilder {

    private ProvContext provContext;
    private List<ProgrammerMessage> jtagCommands;
    private AesGcmProvider encryptionProvider;
    private FlowStage flowStage;
    private ProtocolType protocolType;

    public ProvisioningResponseDTOBuilder context(ProvContext provContext) {
        this.provContext = provContext;
        return this;
    }

    public ProvisioningResponseDTOBuilder withMessages(List<ProgrammerMessage> jtagCommands) {
        this.jtagCommands = jtagCommands;
        return this;
    }

    public ProvisioningResponseDTOBuilder encryptionProvider(AesGcmProvider encryptionProvider) {
        this.encryptionProvider = encryptionProvider;
        return this;
    }

    public ProvisioningResponseDTOBuilder flowStage(FlowStage flowStage) {
        this.flowStage = flowStage;
        return this;
    }

    public ProvisioningResponseDTOBuilder protocolType(ProtocolType protocolType) {
        this.protocolType = protocolType;
        return this;
    }

    public ProvisioningResponseDTO build() throws ProvisioningConverterException, EncryptionProviderException {
        throwIfEncryptionProviderIsNotSet();

        ProvContextWithFlow.ProvContextWithFlowBuilder provContextWithFlowBuilder = ProvContextWithFlow
            .builder()
            .flowStage(flowStage)
            .protocolType(protocolType);

        if (provContext != null) {
            provContextWithFlowBuilder.contextData(ProvisioningContextConverter.serialize(provContext));
        }

        byte[] serializedWithFlow = ProvisioningContextConverter
            .serialize(provContextWithFlowBuilder.build());
        final byte[] encrypted = encryptionProvider.encrypt(serializedWithFlow);
        final ContextDTO encoded = ContextDTO.from(encrypted);

        final List<MessageDTO> jtagCommandsEncoded = ProvisioningContextConverter.encodeMessages(jtagCommands);

        return new ProvisioningResponseDTO(encoded, CONTINUE, jtagCommandsEncoded);
    }

    public ProvisioningResponseDTO done() {
        final List<MessageDTO> jtagCommandsEncoded =
            ProvisioningContextConverter.encodeMessages(Optional.ofNullable(jtagCommands).orElse(List.of()));
        return new ProvisioningResponseDTO(ContextDTO.empty(), DONE,
            jtagCommandsEncoded);
    }

    private void throwIfEncryptionProviderIsNotSet() throws EncryptionProviderException {
        if (encryptionProvider == null) {
            throw new EncryptionProviderException("Context encryption provider is not set.");
        }
    }

}
