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

import com.intel.bkp.bkps.protocol.sigma.model.ProvContextEnc;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MessageResponseCounterManagerTest {

    private static final int CURRENT_COUNTER = 1;
    private static final ProvContextEnc PROV_CONTEXT = ProvContextEnc.builder()
        .messageResponseCounter(CURRENT_COUNTER).build();

    @Test
    void forVerification() {
        // when
        int result = MessageResponseCounterManager.forVerification(PROV_CONTEXT);

        // then
        assertEquals(CURRENT_COUNTER + 1, result);
    }

    @Test
    void forEncryption() {
        // when
        int result = MessageResponseCounterManager.forEncryption(PROV_CONTEXT);

        // then
        assertEquals(CURRENT_COUNTER + 2, result);
    }

    @Test
    void forEncryptionBytes() {
        // when
        byte[] result = MessageResponseCounterManager.forEncryptionBytes(PROV_CONTEXT);

        // then
        assertEquals(CURRENT_COUNTER + 2, ByteBuffer.wrap(result).getInt());
    }
}
