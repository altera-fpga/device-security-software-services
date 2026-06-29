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

package com.intel.bkp.command.messages.spdm;


import com.intel.bkp.utils.ByteBufferSafe;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.nio.ByteBuffer;

@Slf4j
@Getter(AccessLevel.PACKAGE)
public class MctpMessageParser {

    static final int MESSAGE_TYPE_POSITION = 3;
    static final int SECURE_MCTP_MESSAGE_TYPE = 0x06;
    private static final byte MCTP_HEADER_SIZE = Integer.BYTES;
    private static final byte SESSIONID_SIZE = Integer.BYTES;

    public MctpMessage parse(byte[] messageBytes) {
        final ByteBufferSafe buffer = ByteBufferSafe.wrap(messageBytes);

        final byte[] header = new byte[MCTP_HEADER_SIZE];
        buffer.get(header);

        byte[] sessionId = new byte[0];
        if (SECURE_MCTP_MESSAGE_TYPE == header[MESSAGE_TYPE_POSITION]) {
            sessionId = new byte[SESSIONID_SIZE];
            buffer.get(sessionId);
        }

        return new MctpMessage(header, sessionId, buffer.getRemaining());
    }

    public MctpMessage parse(ByteBuffer message) {
        final byte[] messageBytes = new byte[message.remaining()];
        message.get(messageBytes);
        return parse(messageBytes);
    }
}
