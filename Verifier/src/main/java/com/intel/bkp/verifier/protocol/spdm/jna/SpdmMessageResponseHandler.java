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

package com.intel.bkp.verifier.protocol.spdm.jna;

import com.intel.bkp.command.messages.spdm.MctpMessage;
import com.intel.bkp.command.messages.spdm.MctpMessageParser;
import com.intel.bkp.command.messages.spdm.SpdmMessageResponse;
import com.intel.bkp.command.messages.spdm.SpdmMessageResponseParser;
import com.intel.bkp.protocol.spdm.jna.model.MessageLogger;
import lombok.extern.slf4j.Slf4j;

import java.nio.ByteBuffer;

@Slf4j
public class SpdmMessageResponseHandler implements MessageLogger {

    @Override
    public void logMessage(ByteBuffer buffer) {
        final MctpMessage mctp = parseMctpMessage(buffer);
        log.debug("MCTP Header: {}, SPDM Message: {}", mctp, parseSpdmMessageResponse(mctp.getPayloadBuffer()));
    }

    @Override
    public void logResponse(ByteBuffer buffer) {
        final MctpMessage mctp = parseMctpMessage(buffer);
        log.debug("MCTP Header: {}, SPDM Response: {}", mctp, parseSpdmMessageResponse(mctp.getPayloadBuffer()));
    }

    private MctpMessage parseMctpMessage(ByteBuffer buffer) {
        return new MctpMessageParser().parse(buffer.asReadOnlyBuffer());
    }

    private static SpdmMessageResponse parseSpdmMessageResponse(ByteBuffer buffer) {
        return new SpdmMessageResponseParser().parse(buffer.asReadOnlyBuffer());
    }
}
