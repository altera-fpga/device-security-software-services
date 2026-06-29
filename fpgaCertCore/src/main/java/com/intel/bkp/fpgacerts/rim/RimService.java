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

package com.intel.bkp.fpgacerts.rim;

import com.intel.bkp.fpgacerts.dice.tcbinfo.MeasurementHolder;
import com.intel.bkp.fpgacerts.utils.VerificationStatusLogger;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Optional;

import static java.util.Objects.nonNull;

@Slf4j
@RequiredArgsConstructor
public class RimService {

    private static final String PARSED_MSG_TEMPLATE = "Parsed RIM in %s format.";

    private final List<IRimHandler<?>> rimHandlers;

    public MeasurementHolder getMeasurements(String refMeasurementHex) {
        Optional<MeasurementHolder> measurements = Optional.empty();
        final var it = rimHandlers.listIterator();
        while (measurements.isEmpty() && it.hasNext()) {
            final var rimHandler = it.next();
            measurements = getMeasurements(refMeasurementHex, rimHandler);
        }
        return measurements
            .orElseThrow(() -> new IllegalArgumentException("Unknown RIM content format."));
    }

    private <T> Optional<MeasurementHolder> getMeasurements(String refMeasurementHex,
                                                            IRimHandler<T> rimHandler) {
        final Optional<T> parsedRim = parse(refMeasurementHex, rimHandler);
        return parsedRim.map(rimHandler::getMeasurements);
    }

    // TODO Silently gather data about exception if none of handlers succeed
    //  -> log all exception msgs from available handlers
    private <T> Optional<T> parse(String refMeasurementHex, IRimHandler<T> rimHandler) {
        final String formatName = rimHandler.getFormatName();
        log.debug("Parsing RIM content in {} format.", formatName);
        try {
            final T parsedRim = rimHandler.parse(refMeasurementHex);
            if (nonNull(parsedRim)) {
                log.info(VerificationStatusLogger.success(PARSED_MSG_TEMPLATE.formatted(formatName)));
            }
            return Optional.ofNullable(parsedRim);
        } catch (Exception e) {
            log.warn(VerificationStatusLogger.failure(PARSED_MSG_TEMPLATE.formatted(formatName)), e);
            return Optional.empty();
        }
    }
}
