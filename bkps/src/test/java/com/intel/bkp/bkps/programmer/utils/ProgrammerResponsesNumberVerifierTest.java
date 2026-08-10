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

import com.intel.bkp.bkps.exception.ProgrammerResponseNumberException;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.model.ResponseStatus;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ProgrammerResponsesNumberVerifierTest {

    @Test
    void verifyNumberOfResponses_Success() {
        // given
        final int expected = 2;
        List<ProgrammerResponse> responses = generateResponses(expected);

        // when-then
        assertDoesNotThrow(() -> ProgrammerResponsesNumberVerifier.verifyNumberOfResponses(responses, expected));
    }

    @Test
    void verifyNumberOfResponses_WithLessResponsesThanExpected_Throws() {
        // given
        final int expected = 2;
        List<ProgrammerResponse> responses = generateResponses(1);

        // when-then
        assertThrows(ProgrammerResponseNumberException.class,
            () -> ProgrammerResponsesNumberVerifier.verifyNumberOfResponses(responses, expected));
    }

    @Test
    void verifyNumberOfResponses_WithMoreResponsesThanExpected_Throws() {
        // given
        final int expected = 2;
        List<ProgrammerResponse> responses = generateResponses(3);

        // when-then
        assertThrows(ProgrammerResponseNumberException.class,
            () -> ProgrammerResponsesNumberVerifier.verifyNumberOfResponses(responses, expected));
    }

    @Test
    void testVerifyNumberOfResponses_Success() {
        // given
        final int min = 1;
        final int max = 3;
        List<ProgrammerResponse> responses = generateResponses(2);

        // when-then
        assertDoesNotThrow(() -> ProgrammerResponsesNumberVerifier.verifyNumberOfResponses(responses, min, max));
    }

    @Test
    void testVerifyNumberOfResponses_WithMoreResponsesThanThreshold_Throws() {
        // given
        final int min = 1;
        final int max = 3;
        List<ProgrammerResponse> responses = generateResponses(4);

        // when-then
        assertThrows(ProgrammerResponseNumberException.class,
            () -> ProgrammerResponsesNumberVerifier.verifyNumberOfResponses(responses, min, max));
    }

    @Test
    void testVerifyNumberOfResponses_WithLessResponsesThanThreshold_Throws() {
        // given
        final int min = 1;
        final int max = 3;
        List<ProgrammerResponse> responses = generateResponses(0);

        // when-then
        assertThrows(ProgrammerResponseNumberException.class,
            () -> ProgrammerResponsesNumberVerifier.verifyNumberOfResponses(responses, min, max));
    }

    private List<ProgrammerResponse> generateResponses(int size) {
        final List<ProgrammerResponse> responses = new ArrayList<>();
        for (int inc = 0; inc < size; inc++) {
            responses.add(new ProgrammerResponse(("dummy" + inc).getBytes(StandardCharsets.UTF_8), ResponseStatus.ST_OK));
        }
        return responses;
    }
}
