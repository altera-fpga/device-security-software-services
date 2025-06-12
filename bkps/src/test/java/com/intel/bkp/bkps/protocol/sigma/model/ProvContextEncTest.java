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

package com.intel.bkp.bkps.protocol.sigma.model;

import com.intel.bkp.test.RandomUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
public class ProvContextEncTest {

    private static final int DEFAULT_VALUE = -2;

    @Test
    void constructor_VerifyDefaultValueWithBuilder() {
        // when
        final ProvContextEnc provContext = ProvContextEnc.builder().build();

        // then
        assertEquals(DEFAULT_VALUE, provContext.getMessageResponseCounter());
    }

    @Test
    void constructor_VerifyDefaultValueWithConstructor() {
        // when
        final ProvContextEnc provContext = new ProvContextEnc();

        // then
        assertEquals(DEFAULT_VALUE, provContext.getMessageResponseCounter());
    }

    @Test
    void constructor_VerifyBuilder() {
        // given
        final Long expectedCfgId = 1L;
        final int expectedCounter = 15;
        final byte[] expectedChipId = RandomUtils.generateDeviceId();
        final byte[] expectedSek = new byte[] { 1, 2, 3, 4 };
        final byte[] expectedSmk = new byte[] { 0, 0, 0, 2 };
        final byte[] expectedSdmSessionId = new byte[] { 0, 0, 0, 1 };
        final byte[] expectedIv = new byte[] { 5, 4, 3, 2 };

        // when
        final ProvContextEnc provContext = ProvContextEnc.builder()
            .cfgId(expectedCfgId)
            .chipId(expectedChipId)
            .sessionEncryptionKey(expectedSek)
            .sessionMacKey(expectedSmk)
            .sdmSessionId(expectedSdmSessionId)
            .sigmaEncIv(expectedIv)
            .messageResponseCounter(expectedCounter)
            .build();

        // then
        assertEquals(expectedCfgId, provContext.getCfgId());
        assertEquals(expectedChipId, provContext.getChipId());
        assertArrayEquals(expectedSek, provContext.getSessionEncryptionKey());
        assertArrayEquals(expectedSmk, provContext.getSessionMacKey());
        assertArrayEquals(expectedSdmSessionId, provContext.getSdmSessionId());
        assertArrayEquals(expectedIv, provContext.getSigmaEncIv());
        assertEquals(expectedCounter, provContext.getMessageResponseCounter());
    }
}
