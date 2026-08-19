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

package com.intel.bkp.fpgacerts.ect;

import com.intel.bkp.fpgacerts.cbor.EnvironmentMapBuilder;
import com.intel.bkp.fpgacerts.cbor.MeasurementMapBuilder;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.utils.HexConverter;
import com.upokecenter.cbor.CBORObject;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

@Getter
@Builder
@AllArgsConstructor
public class ECTMap {

    private final CBORObject environment;
    private final List<ElementMap> elementList;
    @Builder.Default
    private final Optional<List<String>> authority = Optional.empty();
    @Builder.Default
    private final Optional<String> cmtype = Optional.empty();

    public enum CMType {
        REFERENCE_VALUES,
        ENDORSEMENTS,
        EVIDENCE,
        ATTESTATION_RESULTS,
        VERIFIER,
        POLICY,
        DOMAIN_MEMBER
    }

    public static IECTMapStorage createEvECTMap(List<TcbInfoMeasurement> conditionTcbInfoMeasurements,
                                                List<TcbInfoMeasurement> endorseTcbInfoMeasurements,
                                                List<String> trustedAuthorityHash) {
        List<ECTMap> conditionEctMapList = new ArrayList<>();
        for (var tcbInfoMeasurement : conditionTcbInfoMeasurements) {
            var environmentMap = EnvironmentMapBuilder.from(tcbInfoMeasurement.getKey());
            var measurementMap = MeasurementMapBuilder.from(tcbInfoMeasurement.getValue());
            ElementMap elementMap = ElementMap.builder()
                .elementClaims(measurementMap)
                .build();
            ECTMap map = builder()
                        .environment(environmentMap)
                        .elementList(List.of(elementMap))
                        .build();
            conditionEctMapList.add(map);
        }
        List<ECTMap> additionEctMapList = new ArrayList<>();
        for (var tcbInfoMeasurement : endorseTcbInfoMeasurements) {
            var environmentMap = EnvironmentMapBuilder.from(tcbInfoMeasurement.getKey());
            var measurementMap = MeasurementMapBuilder.from(tcbInfoMeasurement.getValue());
            ElementMap elementMap = ElementMap.builder()
                .elementClaims(measurementMap)
                .build();
            ECTMap map = builder()
                        .environment(environmentMap)
                        .elementList(List.of(elementMap))
                        .authority(Optional.ofNullable(trustedAuthorityHash))
                        .cmtype(Optional.of(CMType.ENDORSEMENTS.name().toUpperCase()))
                        .build();
            additionEctMapList.add(map);
        }
        var ev = IECTMapStorage.builder()
                .condition(conditionEctMapList)
                .addition(additionEctMapList)
                .build();
        return ev;
    }

    public static List<IECTMapStorage> createRvECTMap(List<TcbInfoMeasurement> tcbInfoMeasurements,
                                                      List<String> trustedAuthorityHash) {
        List<IECTMapStorage> rvList = new ArrayList<>();
        for (var tcbInfoMeasurement : tcbInfoMeasurements) {
            var environmentMap = EnvironmentMapBuilder.from(tcbInfoMeasurement.getKey());
            var measurementMap = MeasurementMapBuilder.from(tcbInfoMeasurement.getValue());
            ElementMap elementMap = ElementMap.builder()
                .elementClaims(measurementMap)
                .build();
            ECTMapBuilder mapBuilder = builder()
                .environment(environmentMap)
                .elementList(List.of(elementMap));
            var rvBuilder = IECTMapStorage.builder();
            rvBuilder.condition(List.of(mapBuilder.build()));
            mapBuilder.authority(Optional.ofNullable(trustedAuthorityHash));
            mapBuilder.cmtype(Optional.of(CMType.REFERENCE_VALUES.name().toUpperCase()));
            var rv = rvBuilder.addition(List.of(mapBuilder.build())).build();
            rvList.add(rv);
        }
        return rvList;
    }

    public static IECTMapStorage createAeECTMap(List<TcbInfoMeasurement> tcbInfoMeasurements,
                                                List<String> trustedAuthorityHash) {
        List<ECTMap> additionEctMapList = new ArrayList<>();
        for (var tcbInfoMeasurement : tcbInfoMeasurements) {
            var environmentMap = EnvironmentMapBuilder.from(tcbInfoMeasurement.getKey());
            var measurementMap = MeasurementMapBuilder.from(tcbInfoMeasurement.getValue());
            ElementMap elementMap = ElementMap.builder()
                .elementClaims(measurementMap)
                .build();
            ECTMap ectMap = builder()
                .environment(environmentMap)
                .elementList(List.of(elementMap))
                .authority(Optional.ofNullable(trustedAuthorityHash))
                .cmtype(Optional.of(CMType.EVIDENCE.name().toUpperCase()))
                .build();
            additionEctMapList.add(ectMap);
        }

        var ae = IECTMapStorage.builder()
                .addition(additionEctMapList)
                .build();
        return ae;
    }

    public static IECTMapStorage createPolicyECTMap(List<TcbInfoMeasurement> conditionTcbInfoMeasurements,
                                                    List<String> trustedAuthorityHash,
                                                    CMType cmType) {
        List<ECTMap> conditionEctMapList = new ArrayList<>();
        for (var tcbInfoMeasurement : conditionTcbInfoMeasurements) {
            var environmentMap = EnvironmentMapBuilder.from(tcbInfoMeasurement.getKey());
            var measurementMap = MeasurementMapBuilder.from(tcbInfoMeasurement.getValue());
            ElementMap elementMap = ElementMap.builder()
                .elementClaims(measurementMap)
                .build();
            ECTMap map = builder()
                .environment(environmentMap)
                .elementList(List.of(elementMap))
                .authority(Optional.ofNullable(trustedAuthorityHash))
                .cmtype(Optional.of(cmType.name().toUpperCase()))
                .build();
            conditionEctMapList.add(map);
        }
        var policy = IECTMapStorage.builder()
            .condition(conditionEctMapList)
            .build();
        return policy;
    }

    public String toString() {
        String log = """
ECTMap {
    environment:
    %s
    elementList: %s
    authority: %s
    cmtype: %s
}
            """.formatted(
            Optional.ofNullable(environment).map(CBORObject::toString).orElse("null"),
            indentArray(Optional.ofNullable(elementList).orElse(List.of())),
            indentArray(authority.orElse(List.of())),
            cmtype.orElse("null")
        );
        return log;
    }

    private String indentArray(List<? extends Object> str) {
        return Optional.ofNullable(str)
            .map(list -> list.stream()
                .map(e -> e.toString())
                .collect(Collectors.joining(",\n\t\t", "[\n\t\t", "\n\t]\n")))
                .orElse("null");
    }

    @Override
    public boolean equals(Object obj) {
        try {
            if (this == obj) {
                return true;
            }

            // 2. Check for null and if the classes are the same
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }

            // 3. Cast the object to the correct type
            ECTMap ectMap = (ECTMap) obj;
            String environmentHex = Optional.ofNullable(environment)
                .map(CBORObject::EncodeToBytes)
                .map(HexConverter::toFormattedHex)
                .orElseThrow();
            String objEnvironmentHex = Optional.ofNullable(ectMap.getEnvironment())
                .map(CBORObject::EncodeToBytes)
                .map(HexConverter::toFormattedHex)
                .orElseThrow();
            return (environmentHex.equals(objEnvironmentHex)
                    && elementList.equals(ectMap.getElementList())
                    && authority.equals(ectMap.getAuthority())
                    && cmtype.equals(ectMap.getCmtype()));
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return Objects.hash(environment, elementList, authority, cmtype);
    }
}
