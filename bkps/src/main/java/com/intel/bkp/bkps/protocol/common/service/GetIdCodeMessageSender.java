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

package com.intel.bkp.bkps.protocol.common.service;

import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.protocol.BaseMessageSender;
import com.intel.bkp.command.logger.CommandLogger;
import com.intel.bkp.command.messages.common.GetIdCode;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.command.responses.common.GetIdCodeResponse;
import com.intel.bkp.command.responses.common.GetIdCodeResponseBuilder;
import com.intel.bkp.fpgacerts.model.Family;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import static com.intel.bkp.bkps.programmer.model.MessageType.SEND_PACKET;
import static com.intel.bkp.command.logger.CommandLoggerValues.GET_IDCODE_MESSAGE;
import static com.intel.bkp.command.logger.CommandLoggerValues.GET_IDCODE_RESPONSE;

@Slf4j
@Component
@RequiredArgsConstructor
public class GetIdCodeMessageSender implements BaseMessageSender<Family> {

    private final CommandLayer commandLayer;

    public ProgrammerMessage create() {
        log.debug("Preparing GET_IDCODE ...");
        final var getIdCode = new GetIdCode();

        final byte[] payload = commandLayer.create(getIdCode, CommandIdentifier.GET_IDCODE);
        CommandLogger.log(getIdCode, GET_IDCODE_MESSAGE, this.getClass());
        return ProgrammerMessage.from(SEND_PACKET, payload);
    }

    public Family retrieve(byte[] response) {
        final GetIdCodeResponse getIdCodeResponse = new GetIdCodeResponseBuilder()
            .parse(commandLayer.retrieve(response, CommandIdentifier.GET_IDCODE))
            .build();

        log.debug("Received JTAG IDCODE: {}", getIdCodeResponse);
        CommandLogger.log(getIdCodeResponse, GET_IDCODE_RESPONSE, this.getClass());
        return Family.from(getIdCodeResponse.getFamilyId());
    }
}
