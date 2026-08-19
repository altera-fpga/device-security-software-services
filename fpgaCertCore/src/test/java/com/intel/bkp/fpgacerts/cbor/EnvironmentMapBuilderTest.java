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

package com.intel.bkp.fpgacerts.cbor;

import com.intel.bkp.fpgacerts.cbor.rim.RimSigned;
import com.intel.bkp.fpgacerts.cbor.rim.comid.mapping.ReferenceTripleToTcbInfoMeasurementMapper;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimSignedParser;
import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;

import com.intel.bkp.test.rim.OneKeyGenerator;
import com.intel.bkp.test.rim.RimGenerator;
import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId.ECDSA_384;
import static com.intel.bkp.test.RandomUtils.generateRandomHex;
import static java.util.Optional.ofNullable;
import static org.junit.jupiter.api.Assertions.assertEquals;

class EnvironmentMapBuilderTest {

    private static CborKeyPair signingKey;
    private ReferenceTripleToTcbInfoMeasurementMapper measurementMapper =
        new ReferenceTripleToTcbInfoMeasurementMapper();
    private static final String issuerKeyId = generateRandomHex(RimGenerator.ISSUER_KEY_LEN);
    private static final String layer0Digest = "6BAE8B8D60F65E825D5BD4011084C7B7C51FE290621BB4B5846AA38BD8D9A67624AFB6"
        + "7AC93E991363829123D52963C0E60AD3B89C36EFDDCFFE72A67FDB75E6";
    private static final String layer1Digest = "B59D6688BC2B5D22073D1A8A14DC5D76583A5B7BCD1E27B811FDE319F25305B18A632D"
        + "24B83AD6EA5125B6CD529C98D3";

    private static byte[] generateSignedRim(boolean designRim,
                                            boolean newCorimFormat,
                                            boolean includeProfile) {
        final byte[] signed = RimGenerator.instance()
            .design(designRim)
            .privateKey(signingKey.getPrivateKey())
            .publicKey(signingKey.getPublicKey())
            .newCorimFormat(newCorimFormat)
            .issuerKeyId(issuerKeyId)
            .layer0Digest(layer0Digest)
            .layer1Digest(layer1Digest)
            .includeProfile(includeProfile)
            .generate();
        return signed;
    }

    @BeforeEach
    void setUp() throws Exception {
        signingKey = OneKeyGenerator.generate(ECDSA_384);
    }

    @Test
    void convertToCborObject() {
        final byte[] fwCorim = generateSignedRim(false, false, true);
        final RimSigned rimSigned = RimSignedParser.instance().parse(fwCorim);
        List<TcbInfoMeasurement> tcbInfoMeasurements = ofNullable(rimSigned)
            .map(RimSigned::getPayload)
            .map(rim -> rim.getComIds()
                .get(0)
                .getClaims()
                .getReferenceTriples()
                .stream()
                .map(measurementMapper::map)
                .collect(Collectors.toList()))
            .orElse(List.of());

        List<TcbInfoMeasurement> resultTcbInfoMeasurements = new ArrayList<>();
        for (var tcbInfoMeasurement : tcbInfoMeasurements) {
            CBORObject tcbKey = EnvironmentMapBuilder.from(tcbInfoMeasurement.getKey());
            CBORObject tcbValue = MeasurementMapBuilder.from(tcbInfoMeasurement.getValue());
            resultTcbInfoMeasurements.add(new TcbInfoMeasurement(
                EnvironmentMapBuilder.to(tcbKey),
                MeasurementMapBuilder.to(tcbValue)
                ));
        }
        assertEquals(tcbInfoMeasurements, resultTcbInfoMeasurements);
    }

    @Test
    void convertToCborObject_NewFwCoRimFormat() {
        final byte[] fwCorim = generateSignedRim(false, true, false);
        final RimSigned rimSigned = RimSignedParser.instance().parse(fwCorim);
        List<TcbInfoMeasurement> tcbInfoMeasurements = ofNullable(rimSigned)
            .map(RimSigned::getPayload)
            .map(rim -> rim.getComIds()
                .get(0)
                .getClaims()
                .getReferenceTriples()
                .stream()
                .map(measurementMapper::map)
                .collect(Collectors.toList()))
            .orElse(List.of());

        List<TcbInfoMeasurement> resultTcbInfoMeasurements = new ArrayList<>();
        for (var tcbInfoMeasurement : tcbInfoMeasurements) {
            CBORObject tcbKey = EnvironmentMapBuilder.from(tcbInfoMeasurement.getKey());
            CBORObject tcbValue = MeasurementMapBuilder.from(tcbInfoMeasurement.getValue());
            resultTcbInfoMeasurements.add(new TcbInfoMeasurement(
                EnvironmentMapBuilder.to(tcbKey),
                MeasurementMapBuilder.to(tcbValue)
            ));
        }
        assertEquals(tcbInfoMeasurements, resultTcbInfoMeasurements);
    }
}
