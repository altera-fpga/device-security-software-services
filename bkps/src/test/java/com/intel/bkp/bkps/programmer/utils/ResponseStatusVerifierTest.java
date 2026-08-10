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

package com.intel.bkp.bkps.programmer.utils;

import com.intel.bkp.bkps.exception.ProgrammerResponseStatusVerifierException;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.model.ResponseStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static com.intel.bkp.bkps.programmer.utils.ResponseStatusVerifier.EXCEPTION_MESSAGE;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ResponseStatusVerifierTest {

    private static final byte[] VALUE = {1, 2, 3, 4};

    private List<ProgrammerResponse> jtagResponses;

    @BeforeEach
    void setUp() {
        jtagResponses = new ArrayList<>();
    }

    @Test
    void verify_WithEmpty() {
        // when-then
        assertDoesNotThrow(() -> ResponseStatusVerifier.verify(jtagResponses));
    }

    @Test
    void verify_With2Ok() {
        // given
        jtagResponses.add(new ProgrammerResponse(VALUE, ResponseStatus.ST_OK));
        jtagResponses.add(new ProgrammerResponse(VALUE, ResponseStatus.ST_OK));

        // when-then
        assertDoesNotThrow(() -> ResponseStatusVerifier.verify(jtagResponses));
    }

    @Test
    void verify_With1Ok1Fail_Throws() {
        // given
        jtagResponses.add(new ProgrammerResponse(VALUE, ResponseStatus.ST_OK));
        jtagResponses.add(new ProgrammerResponse(VALUE, ResponseStatus.ST_GENERIC_ERROR));

        // when-then
        final var ex = assertThrows(ProgrammerResponseStatusVerifierException.class,
            () -> ResponseStatusVerifier.verify(jtagResponses));

        assertEquals(EXCEPTION_MESSAGE, ex.getMessage());
    }

    @Test
    void verify_With1Ok2Fail_Throws() {
        // given
        jtagResponses.add(new ProgrammerResponse(VALUE, ResponseStatus.ST_OK));
        jtagResponses.add(new ProgrammerResponse(VALUE, ResponseStatus.ST_GENERIC_ERROR));
        jtagResponses.add(new ProgrammerResponse(VALUE, ResponseStatus.ST_GENERIC_ERROR));

        // when-then
        final var ex = assertThrows(ProgrammerResponseStatusVerifierException.class,
            () -> ResponseStatusVerifier.verify(jtagResponses));

        assertEquals(EXCEPTION_MESSAGE, ex.getMessage());
    }
}
