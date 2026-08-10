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

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class DecryptedPayloadTest {

    @Test
    void from_ValidMagic() {
        // given
        int paddingLen = 50;
        byte[] payload = new EncryptedPayload(new byte[]{1, 2}, new byte[paddingLen]).build();

        // when
        DecryptedPayload result = DecryptedPayload.from(payload, paddingLen);

        // then
        assertEquals(EncryptedPayload.PAYLOAD_MAGIC_NUMBER, result.getMagic());
    }

    @Test
    void from_VerifyValues() {
        // given
        int paddingLen = 50;
        byte[] expectedValue = {1, 2};
        byte[] expectedPadding = new byte[paddingLen];
        byte[] expectedReserved = new byte[DecryptedPayload.RESERVED_LEN];
        byte[] payload = new EncryptedPayload(expectedValue, expectedPadding).build();

        // when
        DecryptedPayload result = DecryptedPayload.from(payload, paddingLen);

        // then
        assertArrayEquals(expectedReserved, result.getReserved());
        assertArrayEquals(expectedValue, result.getValue());
        assertArrayEquals(expectedPadding, result.getPadding());
    }

    @Test
    void from_InvalidLen_Throws() {
        // given
        byte[] payload = new byte[1];

        // when
        assertThrows(Exception.class, () -> DecryptedPayload.from(payload, 2));
    }

    @Test
    void from_InvalidMagic_Throws() {
        // given
        int paddingLen = 50;
        byte[] payload =
            ByteBuffer.allocate(DecryptedPayload.MAGIC_LEN + DecryptedPayload.RESERVED_LEN + paddingLen).array();

        // when
        assertThrows(Exception.class, () -> DecryptedPayload.from(payload, paddingLen));
    }
}
