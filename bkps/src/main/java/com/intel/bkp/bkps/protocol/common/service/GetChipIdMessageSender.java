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
import com.intel.bkp.command.messages.common.GetChipIdMessageBuilder;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.command.responses.common.GetChipIdResponse;
import com.intel.bkp.command.responses.common.GetChipIdResponseBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Locale;

import static com.intel.bkp.bkps.programmer.model.MessageType.SEND_PACKET;
import static com.intel.bkp.command.logger.CommandLoggerValues.GET_CHIPID_MESSAGE;
import static com.intel.bkp.command.logger.CommandLoggerValues.GET_CHIPID_RESPONSE;
import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
@Component
@RequiredArgsConstructor
public class GetChipIdMessageSender implements BaseMessageSender<String> {

    private final CommandLayer commandLayer;

    public ProgrammerMessage create() {
        log.debug("Preparing GET_CHIPID ...");
        final var message = new GetChipIdMessageBuilder().build();

        final byte[] payload = commandLayer.create(message, CommandIdentifier.GET_CHIPID);
        CommandLogger.log(message, GET_CHIPID_MESSAGE, this.getClass());
        return ProgrammerMessage.from(SEND_PACKET, payload);
    }

    public String retrieve(byte[] response) {
        final GetChipIdResponse chipIdResponse = new GetChipIdResponseBuilder()
            .parse(commandLayer.retrieve(response, CommandIdentifier.GET_CHIPID))
            .build();
        CommandLogger.log(chipIdResponse, GET_CHIPID_RESPONSE, this.getClass());
        return toHex(chipIdResponse.getDeviceUniqueId()).toLowerCase(Locale.ROOT);
    }

}
