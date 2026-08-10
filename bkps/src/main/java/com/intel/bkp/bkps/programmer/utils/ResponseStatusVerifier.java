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
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class ResponseStatusVerifier {

    private static final String LINE_SEPARATOR = System.lineSeparator();
    private static final String LOG_DELIMITER = LINE_SEPARATOR + "\t- ";
    static final String EXCEPTION_MESSAGE = "One of the commands resulted in ST_GENERIC_ERROR.";

    public static void verify(List<ProgrammerResponse> responses) throws ProgrammerResponseStatusVerifierException {
        final var failedProgrammerResponses = responses
            .stream()
            .filter(resp -> ResponseStatus.ST_GENERIC_ERROR.equals(resp.getStatus()))
            .toList();

        if (!failedProgrammerResponses.isEmpty()) {
            log.error("One of the commands resulted in ST_GENERIC_ERROR: {}{}",
                LOG_DELIMITER,
                failedProgrammerResponses.stream().map(Object::toString).collect(Collectors.joining(LOG_DELIMITER)));

            throw new ProgrammerResponseStatusVerifierException(EXCEPTION_MESSAGE);
        }
    }
}
