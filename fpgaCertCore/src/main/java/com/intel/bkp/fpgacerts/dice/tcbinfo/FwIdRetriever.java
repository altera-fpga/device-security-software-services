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

package com.intel.bkp.fpgacerts.dice.tcbinfo;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class FwIdRetriever {

    private final Map<TcbInfoKey, TcbInfoValue> map;

    public static FwIdRetriever instance(Map<TcbInfoKey, TcbInfoValue> map) {
        return new FwIdRetriever(map);
    }

    public Optional<String> getFwId(String familyName, MeasurementType measurementType) {
        return getFwId(familyName, measurementType, (fwIdField) -> FwidHashAlg.isSupported(fwIdField.getHashAlg()));
    }

    public Optional<String> getFwId(String familyName, MeasurementType measurementType, FwidHashAlg hashAlg) {
        return getFwId(familyName, measurementType, hasExpectedHashAlgPredicate(hashAlg));
    }

    private Optional<String> getFwId(String familyName, MeasurementType measurementType,
                                     Predicate<FwIdField> predicate) {
        final var keyForOlderDevices = TcbInfoKey.from(measurementType, familyName);
        final var keyForNewerDevices = TcbInfoKey.from(measurementType);

        return getFwIdField(keyForOlderDevices)
            .or(() -> getFwIdField(keyForNewerDevices))
            .filter(predicate)
            .map(FwIdField::getDigest);
    }

    private Predicate<FwIdField> hasExpectedHashAlgPredicate(FwidHashAlg hashAlg) {
        return fwIdField -> hashAlg.getOid().equals(fwIdField.getHashAlg());
    }

    private Optional<FwIdField> getFwIdField(TcbInfoKey key) {
        return map.containsKey(key)
               ? map.get(key).getFwid()
               : Optional.empty();
    }
}
