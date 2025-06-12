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

package com.intel.bkp.bkps.protocol.common.service;

import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.protocol.BaseMessageSender;
import com.intel.bkp.command.logger.CommandLogger;
import com.intel.bkp.command.messages.sigma.SigmaTeardownMessageBuilder;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.command.responses.sigma.SigmaTeardownResponse;
import com.intel.bkp.command.responses.sigma.SigmaTeardownResponseBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Optional;

import static com.intel.bkp.bkps.programmer.model.MessageType.SEND_PACKET;
import static com.intel.bkp.command.logger.CommandLoggerValues.PSGSIGMA_TEARDOWN_MESSAGE;
import static com.intel.bkp.command.logger.CommandLoggerValues.PSGSIGMA_TEARDOWN_RESPONSE;

@Slf4j
@Component
@RequiredArgsConstructor
public class SigmaTeardownMessageSender implements BaseMessageSender<Optional<Void>> {

    private final CommandLayer commandLayer;

    public ProgrammerMessage create() {
        log.debug("Preparing SIGMA_TEARDOWN ...");
        final var message = new SigmaTeardownMessageBuilder()
            .build();

        final byte[] payload = commandLayer.create(message, CommandIdentifier.SIGMA_TEARDOWN);
        CommandLogger.log(message, PSGSIGMA_TEARDOWN_MESSAGE, this.getClass());
        return ProgrammerMessage.from(SEND_PACKET, payload);
    }

    public Optional<Void> retrieve(byte[] response) {
        final SigmaTeardownResponse sigmaTeardownResponse = new SigmaTeardownResponseBuilder()
            .parse(commandLayer.retrieve(response, CommandIdentifier.SIGMA_TEARDOWN))
            .build();
        CommandLogger.log(sigmaTeardownResponse, PSGSIGMA_TEARDOWN_RESPONSE, this.getClass());
        return Optional.empty();
    }
}
