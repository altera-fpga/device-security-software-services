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

package com.intel.bkp.bkps.domain;

import com.intel.bkp.bkps.domain.enumeration.ContextKeyType;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ContextKeyTest {

    @Mock
    private WrappingKey wrappingKey;

    @Test
    void from() {
        // when
        ContextKey result = ContextKey.from(new byte[1], wrappingKey);

        // then
        assertEquals("AA==", result.getValue());
    }

    @Test
    void from_WithEmpty() {
        // when
        ContextKey result = ContextKey.from(new byte[0], wrappingKey);

        // then
        assertEquals("", result.getValue());
    }

    @Test
    void from_KeyTypeIsActual() {
        // when
        ContextKey result = ContextKey.from(new byte[1], wrappingKey);

        // then
        assertEquals(ContextKeyType.ACTUAL.name(), result.getKeyType());
    }

    @Test
    void from_WrappingKeyIsSet() {
        // when
        ContextKey result = ContextKey.from(new byte[1], wrappingKey);

        // then
        assertEquals(wrappingKey, result.getWrappingKey());
    }

    @Test
    void decoded() {
        // given
        byte[] expected = new byte[1];
        ContextKey key = ContextKey.from(expected, wrappingKey);

        // when
        assertArrayEquals(expected, key.decoded());
    }

    @Test
    void decoded_2() {
        // given
        byte[] expected = { 1, 2, 3 };
        ContextKey key = ContextKey.from(expected, wrappingKey);

        // when
        assertArrayEquals(expected, key.decoded());
    }

    @Test
    void decoded_FromString() {
        // given
        byte[] expected = { 1, 2, 3 };
        ContextKey key = new ContextKey();
        key.setValue("AQID");

        // when
        assertArrayEquals(expected, key.decoded());
    }
}
