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

package com.intel.bkp.bkps.protocol.common;

import com.intel.bkp.command.messages.BaseMessage;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.utils.PaddingUtils;
import lombok.RequiredArgsConstructor;

import java.nio.ByteBuffer;

import static com.intel.bkp.utils.ByteSwapOrder.B2L;

@RequiredArgsConstructor
public class EncryptedPayload {

    static final int PAYLOAD_MAGIC_NUMBER = 0x5F454E43;

    private final byte[] value;
    private final byte[] padding;

    static final int MSG_PACK_SIZE = 32;
    static final int MAGIC_LEN = Integer.BYTES;
    static final int RESERVED_LEN = Integer.BYTES;
    static final byte[] magic = ByteSwap.getSwappedArray(PAYLOAD_MAGIC_NUMBER, B2L);
    static final byte[] reserved = new byte[RESERVED_LEN];

    public static EncryptedPayload from(byte[] command) {
        byte[] padding = PaddingUtils.getPaddingPacked(getValueNotPadded(command), MSG_PACK_SIZE);
        return new EncryptedPayload(command, padding);
    }

    public static EncryptedPayload from(BaseMessage message) {
        byte[] value = message.array();
        byte[] padding = PaddingUtils.getPaddingPacked(getValueNotPadded(value), MSG_PACK_SIZE);
        return new EncryptedPayload(value, padding);
    }

    public byte[] build() {
        return ByteBuffer.allocate(MAGIC_LEN + RESERVED_LEN + value.length + padding.length)
            .put(magic)
            .put(reserved)
            .put(value)
            .put(padding)
            .array();
    }

    public byte getPaddingLength() {
        return (byte)padding.length;
    }

    private static byte[] getValueNotPadded(byte[] value) {
        return ByteBuffer.allocate(MAGIC_LEN + RESERVED_LEN + value.length)
            .put(magic)
            .put(reserved)
            .put(value)
            .array();
    }
}
