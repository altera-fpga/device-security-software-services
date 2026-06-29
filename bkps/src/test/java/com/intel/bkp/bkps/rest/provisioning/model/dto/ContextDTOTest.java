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

package com.intel.bkp.bkps.rest.provisioning.model.dto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ContextDTOTest {

    @Test
    void from() {
        // when
        ContextDTO result = ContextDTO.from(new byte[1]);

        // then
        assertEquals("AA==", result.getValue());
    }

    @Test
    void from_WithEmpty() {
        // when
        ContextDTO result = ContextDTO.from(new byte[0]);

        // then
        assertEquals("", result.getValue());
    }

    @Test
    void empty() {
        // when
        ContextDTO result = ContextDTO.empty();

        // then
        assertEquals("", result.getValue());
    }

    @Test
    void decoded() {
        // given
        byte[] expected = new byte[1];
        ContextDTO key = ContextDTO.from(expected);

        // when
        assertArrayEquals(expected, key.decoded());
    }

    @Test
    void decoded_2() {
        // given
        byte[] expected = { 1, 2, 3 };
        ContextDTO key = ContextDTO.from(expected);

        // when
        assertArrayEquals(expected, key.decoded());
    }

    @Test
    void decoded_FromString() {
        // given
        byte[] expected = { 1, 2, 3 };
        ContextDTO key = new ContextDTO("AQID");

        // when
        assertArrayEquals(expected, key.decoded());
    }

    @Test
    void isEmpty_False() {
        // given
        ContextDTO key = ContextDTO.from(new byte[1]);

        // when
        boolean result = key.isEmpty();

        // then
        assertFalse(result);
    }

    @Test
    void isEmpty_True() {
        // given
        ContextDTO key = ContextDTO.empty();

        // when
        boolean result = key.isEmpty();

        // then
        assertTrue(result);
    }
}
