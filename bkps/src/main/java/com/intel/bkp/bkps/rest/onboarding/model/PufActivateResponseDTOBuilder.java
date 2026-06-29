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

package com.intel.bkp.bkps.rest.onboarding.model;

import com.intel.bkp.bkps.programmer.model.CommunicationStatus;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.programmer.model.dto.MessageDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ContextDTO;

import java.util.List;
import java.util.Optional;

import static com.intel.bkp.bkps.rest.provisioning.utils.ProvisioningContextConverter.encodeMessages;

public class PufActivateResponseDTOBuilder {

    private List<ProgrammerMessage> jtagCommands;

    public PufActivateResponseDTOBuilder withMessages(List<ProgrammerMessage> jtagCommands) {
        this.jtagCommands = jtagCommands;
        return this;
    }

    public PufActivateResponseDTO build() {
        final List<MessageDTO> encoded = encodeMessages(getValidList());
        return new PufActivateResponseDTO(ContextDTO.empty(), CommunicationStatus.CONTINUE, encoded);
    }

    public PufActivateResponseDTO done() {
        final List<MessageDTO> commandsEncoded = encodeMessages(getValidList());
        return new PufActivateResponseDTO(ContextDTO.empty(), CommunicationStatus.DONE, commandsEncoded);
    }

    private List<ProgrammerMessage> getValidList() {
        return Optional.ofNullable(jtagCommands).orElse(List.of());
    }
}
