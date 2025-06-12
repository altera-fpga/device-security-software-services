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

package com.intel.bkp.bkps.protocol.sigma.session;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@ExtendWith(MockitoExtension.class)
public class SecureSessionIvProviderTest {

    private SecureSessionIvProvider sut;
    private static final byte[] MESSAGE_RESPONSE_COUNTER = { 0x00, 0x00, 0x00, 0x01 } ;

    private SecureSessionIvProvider prepareSut(byte[] initialIv) {
        return new SecureSessionIvProvider(new IMessageResponseCounterProvider() {
            @Override
            public byte[] getInitialIv() {
                return initialIv;
            }

            @Override
            public byte[] getMessageResponseCounter() {
                return MESSAGE_RESPONSE_COUNTER;
            }
        });
    }

    @Test
    void generate_SimpleSumWith00() {
        // given
        final byte[] initialIv = new byte[12];
        final byte[] expectedResult =
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

        sut = prepareSut(initialIv);

        // when
        byte[] result = sut.generate();

        // then
        assertArrayEquals(expectedResult, result);
    }

    @Test
    void generate_SimpleSum() {
        // given
        final byte[] initialIv =
            new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
        final byte[] expectedResult =
            new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0D };

        sut = prepareSut(initialIv);

        // when
        byte[] result = sut.generate();

        // then
        assertArrayEquals(expectedResult, result);
    }

    @Test
    void generate_LastByteIsFF() {
        // given
        final byte[] initialIv =
            new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, -0x01 };
        final byte[] expectedResult =
            new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0C, 0x00 };

        sut = prepareSut(initialIv);

        // when
        byte[] result = sut.generate();

        // then
        assertArrayEquals(expectedResult, result);
    }

    @Test
    void generate_Last4BytesAreFF() {
        // given
        final byte[] initialIv =
            new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, -0x01, -0x01, -0x01, -0x01 };
        final byte[] expectedResult =
            new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00 };

        sut = prepareSut(initialIv);

        // when
        byte[] result = sut.generate();

        // then
        assertArrayEquals(expectedResult, result);
    }
}
