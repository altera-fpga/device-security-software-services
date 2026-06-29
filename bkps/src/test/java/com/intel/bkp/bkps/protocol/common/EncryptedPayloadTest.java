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
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class EncryptedPayloadTest {

    @Test
    void from_With0Padding() {
        // given
        BaseMessage baseMessage = prepareBaseMessageWith(EncryptedPayload.MSG_PACK_SIZE);

        // when
        EncryptedPayload result = EncryptedPayload.from(baseMessage);

        // then
        assertEquals(0, result.getPaddingLength());
    }

    @Test
    void from_With1Padding() {
        // given
        BaseMessage baseMessage = prepareBaseMessageWith(EncryptedPayload.MSG_PACK_SIZE - 1);

        // when
        EncryptedPayload result = EncryptedPayload.from(baseMessage);

        // then
        assertEquals(1, result.getPaddingLength());
    }

    @Test
    void from_With31Padding() {
        // given
        BaseMessage baseMessage = prepareBaseMessageWith(EncryptedPayload.MSG_PACK_SIZE - 31);

        // when
        EncryptedPayload result = EncryptedPayload.from(baseMessage);

        // then
        assertEquals(31, result.getPaddingLength());
    }

    @Test
    void from_With31PaddingBiggerThanPack() {
        // given
        BaseMessage baseMessage = prepareBaseMessageWith(EncryptedPayload.MSG_PACK_SIZE + 1);

        // when
        EncryptedPayload result = EncryptedPayload.from(baseMessage);

        // then
        assertEquals(31, result.getPaddingLength());
    }

    @Test
    void from_With0PaddingMultipleOfPack() {
        // given
        BaseMessage baseMessage = prepareBaseMessageWith(2 * EncryptedPayload.MSG_PACK_SIZE);

        // when
        EncryptedPayload result = EncryptedPayload.from(baseMessage);

        // then
        assertEquals(0, result.getPaddingLength());
    }

    @Test
    void build_With0Padding() {
        // given
        BaseMessage baseMessage = prepareBaseMessageWith(EncryptedPayload.MSG_PACK_SIZE);
        EncryptedPayload payload = EncryptedPayload.from(baseMessage);

        // when
        byte[] result = payload.build();

        // then
        assertEquals(EncryptedPayload.MSG_PACK_SIZE, result.length);
    }

    @Test
    void build_With1Padding() {
        // given
        BaseMessage baseMessage = prepareBaseMessageWith(EncryptedPayload.MSG_PACK_SIZE - 1);
        EncryptedPayload payload = EncryptedPayload.from(baseMessage);

        // when
        byte[] result = payload.build();

        // then
        assertEquals(EncryptedPayload.MSG_PACK_SIZE, result.length);
    }

    @Test
    void build_VerifyConcatenationOfPadding() {
        // given
        BaseMessage baseMessage = new BaseMessage() {
            @Override
            public byte[] array() {
                return new byte[]{0x01, 0x02};
            }
        };

        byte[] expected = ByteBuffer.allocate(EncryptedPayload.MSG_PACK_SIZE)
            .put(EncryptedPayload.magic)
            .put(EncryptedPayload.reserved)
            .put((byte) 0x01)
            .put((byte) 0x02)
            .array();

        EncryptedPayload payload = EncryptedPayload.from(baseMessage);

        // when
        byte[] result = payload.build();

        // then
        assertArrayEquals(expected, result);
    }

    private BaseMessage prepareBaseMessageWith(int messageSize) {
        return new BaseMessage() {
            @Override
            public byte[] array() {
                int recalculatedBaseMessageLen =
                    (messageSize + EncryptedPayload.MSG_PACK_SIZE - EncryptedPayload.MAGIC_LEN -
                        EncryptedPayload.RESERVED_LEN) % EncryptedPayload.MSG_PACK_SIZE;
                return new byte[recalculatedBaseMessageLen];
            }
        };
    }
}
