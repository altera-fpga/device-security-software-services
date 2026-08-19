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
import com.intel.bkp.fpgacerts.cbor.rim.RimSigned;
import com.intel.bkp.fpgacerts.cbor.rim.comid.EnvironmentMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion;
import com.intel.bkp.fpgacerts.cbor.rim.comid.mapping.ReferenceTripleToTcbInfoMeasurementMapper;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimSignedParser;
import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoExtensionParser;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement.asMeasurements;
import static com.intel.bkp.fpgacerts.utils.X509UtilsWrapper.toX509;
import static com.intel.bkp.test.FileUtils.readFromResources;
import com.intel.bkp.test.rim.OneKeyGenerator;
import com.intel.bkp.test.rim.RimGenerator;
import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId.ECDSA_384;
import static com.intel.bkp.test.RandomUtils.generateRandomHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static java.util.Optional.ofNullable;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class ECTMapTest {

    private final List<String> trustedRootHash = List.of("35E08599DD52CB7533764DEE65C915BBAFD0E35E6252BCCD77F3A694390F618B");
    private static CborKeyPair signingKey;
    private ReferenceTripleToTcbInfoMeasurementMapper measurementMapper = new ReferenceTripleToTcbInfoMeasurementMapper();
    private static final String issuerKeyId = generateRandomHex(RimGenerator.ISSUER_KEY_LEN);
    private static final String layer0Digest = "6BAE8B8D60F65E825D5BD4011084C7B7C51FE290621BB4B5846AA38BD8D9A67624AFB6"
                                                + "7AC93E991363829123D52963C0E60AD3B89C36EFDDCFFE72A67FDB75E6";
    private static final String layer1Digest = "B59D6688BC2B5D22073D1A8A14DC5D76583A5B7BCD1E27B811FDE319F25305B18A632D"
                                                + "24B83AD6EA5125B6CD529C98D3";
    private final TcbInfoExtensionParser tcbInfoExtensionParser = new TcbInfoExtensionParser();
    private static X509Certificate aliasCert;
    private static final String TEST_FOLDER_INTEGRATION = "certs/dice/";
    private static final String ALIAS_CERT = "alias_certificate.der";

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

    private List<CBORObject> getEnvironmentMap(ECTMap ectMap,
                                               String expectedClassOid,
                                               String expectedVendor,
                                               String expectedModel,
                                               Integer expectedLayer,
                                               Integer expectedIndex) {
        return ofNullable(ectMap).stream()
                .map(ECTMap::getEnvironment)
                .filter(env -> env.ContainsKey(EnvironmentMap.CBOR_CLASS_ID_KEY))
                .filter(env -> ofNullable(env.get(EnvironmentMap.CBOR_CLASS_ID_KEY))
                    .map(classMap -> classMap.get(EnvironmentMap.CBOR_CLASS_ID_KEY))
                    .map(classId -> classId.toString().equals(expectedClassOid))
                    .orElse(true))
                .filter(env -> ofNullable(env.get(EnvironmentMap.CBOR_CLASS_ID_KEY))
                    .map(classMap -> classMap.get(EnvironmentMap.CBOR_VENDOR_KEY))
                    .map(vendor -> vendor.AsString().equals(expectedVendor))
                    .orElse(true))
                .filter(env -> ofNullable(env.get(EnvironmentMap.CBOR_CLASS_ID_KEY))
                    .map(classMap -> classMap.get(EnvironmentMap.CBOR_MODEL_KEY))
                    .map(model -> model.AsString().equals(expectedModel))
                    .orElse(true))
                .filter(env -> ofNullable(env.get(EnvironmentMap.CBOR_CLASS_ID_KEY))
                    .map(classMap -> classMap.get(EnvironmentMap.CBOR_LAYER_KEY))
                    .map(layer -> layer.AsInt32() == expectedLayer)
                    .orElse(true))
                .filter(env -> ofNullable(env.get(EnvironmentMap.CBOR_CLASS_ID_KEY))
                    .map(classMap -> classMap.get(EnvironmentMap.CBOR_INDEX_KEY))
                    .map(index -> index.AsInt32() == expectedIndex)
                    .orElse(true))
                .collect(Collectors.toList());
    }

    private List<CBORObject> getClaims(ECTMap ectMap, String layerDigest) {
        return ofNullable(ectMap.getElementList()).stream()
                .flatMap(list -> list.stream().map(ElementMap::getElementClaims)
                    .filter(claim -> ofNullable(claim.get(MeasurementMap.CBOR_DIGESTS_KEY))
                        .map(digestArr -> digestArr.get(0).get(0).AsInt32() == 7 &&
                            toHex(digestArr.get(0).get(1).GetByteString()).equals(layerDigest))
                        .orElse(true))
                    .filter(claim -> ofNullable(claim.get(MeasurementMap.CBOR_MEAS_VERSION_KEY))
                        .map(versionMap -> versionMap.get(MeasurementVersion.CBOR_VERSION_KEY).AsString().equals("release-2023.28.1.1") &&
                            versionMap.get(MeasurementVersion.CBOR_VERSION_SCHEME_KEY).AsInt32() == 3)
                        .orElse(true)
                    ))
                .collect(Collectors.toList());
    }

    private void verifyCondition(ECTMap condition,
                                 String expectedClassOid,
                                 String expectedVendor,
                                 String expectedModel,
                                 Integer expectedLayer,
                                 Integer expectedIndex,
                                 String layerDigest) {
        assertFalse(getEnvironmentMap(
            condition,
            expectedClassOid,
            expectedVendor,
            expectedModel,
            expectedLayer,
            expectedIndex)
            .isEmpty());
        assertEquals(getClaims(condition, layerDigest).size(), 1);
        assertEquals(condition.getAuthority(), Optional.empty());
        assertEquals(condition.getCmtype(), Optional.empty());
    }

    private void verifyAddition(ECTMap addition,
                                String expectedClassOid,
                                String expectedVendor,
                                String expectedModel,
                                Integer expectedLayer,
                                Integer expectedIndex,
                                String layerDigest,
                                String cmType) {
        assertFalse(getEnvironmentMap(
            addition,
            expectedClassOid,
            expectedVendor,
            expectedModel,
            expectedLayer,
            expectedIndex)
            .isEmpty());
        assertEquals(getClaims(addition, layerDigest).size(), 1);
        assertEquals(addition.getAuthority(), ofNullable(trustedRootHash));
        assertEquals(addition.getCmtype(), ofNullable(cmType));
    }

    private void verifyRvList(IECTMapStorage referenceValuesECTMapStorage,
                              String expectedClassOid,
                              String expectedVendor,
                              String expectedModel,
                              Integer expectedLayer,
                              Integer expectedIndex,
                              String layerDigest,
                              String cmType) {
        for (var condition : referenceValuesECTMapStorage.getCondition()) {
            verifyCondition(condition,
                expectedClassOid,
                expectedVendor,
                expectedModel,
                expectedLayer,
                expectedIndex,
                layerDigest);
        }

        for (var addition : referenceValuesECTMapStorage.getAddition()) {
            verifyAddition(addition,
                expectedClassOid,
                expectedVendor,
                expectedModel,
                expectedLayer,
                expectedIndex,
                layerDigest,
                cmType);
        }
    }

    private List<TcbInfoMeasurement> getMeasurementsFromCertificate(X509Certificate aliasCert) {
        return asMeasurements(tcbInfoExtensionParser.parse(aliasCert));
    }

    @BeforeEach
    void setUp() throws Exception {
        signingKey = OneKeyGenerator.generate(ECDSA_384);
    }

    @Test
    void createRVEctMap_withEmptyList() {
        var rvList = ECTMap.createRvECTMap(List.of(), trustedRootHash);
        assertEquals(0, rvList.toArray().length);
    }

    @Test
    void createEVEctMap_withEmptyList() {
        var ev = ECTMap.createEvECTMap(List.of(), List.of(), trustedRootHash);
        assertEquals(0, ev.getCondition().toArray().length);
        assertEquals(0, ev.getAddition().toArray().length);
    }

    @Test
    void createAEEctMap_withEmptyList() {
        var ae = ECTMap.createAeECTMap(List.of(), trustedRootHash);
        assertEquals(0, ae.getAddition().toArray().length);
    }

    @Test
    void createRVEctMap() {
        final byte[] fwCorim = generateSignedRim(false, false, false);
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
        var rvList = ECTMap.createRvECTMap(tcbInfoMeasurements, trustedRootHash);
        var tcbKey = EnvironmentMapBuilder.to(rvList.get(0).getCondition().get(0).getEnvironment());
        var tcbValue = MeasurementMapBuilder.to(rvList.get(0).getCondition().get(0).getElementList().get(0).getElementClaims());
        assertEquals(2, rvList.toArray().length);
        verifyRvList(rvList.get(0),
                     "",
                     "intel.com",
                     "Agilex",
                     0,
                     0,
                     layer0Digest,
                     ECTMap.CMType.REFERENCE_VALUES.name());
        verifyRvList(rvList.get(1),
                    "",
                    "intel.com",
                    "Agilex",
                    1,
                    0,
                    layer1Digest,
                    ECTMap.CMType.REFERENCE_VALUES.name());
    }

    @Test
    void createEVEctMap() {
        final byte[] fwCorim = generateSignedRim(false, false, false);
        final RimSigned rimSigned = RimSignedParser.instance().parse(fwCorim);
        List<TcbInfoMeasurement> conditions = ofNullable(rimSigned)
            .map(RimSigned::getPayload)
            .map(rim -> rim.getComIds()
                .get(0)
                .getClaims()
                .getReferenceTriples()
                .stream()
                .map(measurementMapper::map)
                .collect(Collectors.toList()))
            .orElse(List.of());
        List<TcbInfoMeasurement> endorsements = ofNullable(rimSigned)
            .map(RimSigned::getPayload)
            .map(rim -> rim.getComIds()
                .get(0)
                .getClaims()
                .getEndorsedTriples()
                .stream()
                .map(measurementMapper::map)
                .collect(Collectors.toList()))
            .orElse(List.of());
        var evList = ECTMap.createEvECTMap(conditions, endorsements, trustedRootHash);
        assertEquals(2, evList.getCondition().toArray().length);
        verifyCondition(evList.getCondition().get(0),
                        "",
                        "intel.com",
                        "Agilex",
                        0,
                        0,
                        layer0Digest);
        verifyCondition(evList.getCondition().get(1),
                        "",
                        "intel.com",
                        "Agilex",
                        1,
                        0,
                        layer1Digest);
        assertEquals(1, evList.getAddition().toArray().length);
        verifyAddition(evList.getAddition().get(0),
                       "111(h'6086480186F84D010F048148')",
                       "intel.com",
                       "Agilex",
                       1,
                       0,
                       layer1Digest,
                       ECTMap.CMType.ENDORSEMENTS.name());
    }

    @Test
    void createAEEctMap() throws Exception {
        aliasCert = toX509(readFromResources(TEST_FOLDER_INTEGRATION, ALIAS_CERT));
        var aeAliasCertList =
            ECTMap.createAeECTMap(getMeasurementsFromCertificate(aliasCert), trustedRootHash);
        assertEquals(2, aeAliasCertList.getAddition().toArray().length);
        verifyAddition(aeAliasCertList.getAddition().get(0),
                        "111(h'6086480186F84D010F0402')",
                        "intel.com",
                        null,
                        2,
                        null,
                        "066331A2C0CD05F2F48D5BDD4EA60C5CFFAE61C286B1ADDE040E1F821EC8199FF76AA3750C8DE1382CDB14B067A8E0E3",
                        ECTMap.CMType.EVIDENCE.name());
        verifyAddition(aeAliasCertList.getAddition().get(1),
                        "111(h'6086480186F84D010F0403')",
                        "intel.com",
                        null,
                        2,
                        null,
                        "FEC20013FCD2D2187176FED7DB8537B93695C845B76F98658FCC8350EE5341FC196D8CBCE4DDA1098B075AE67F148D73",
                        ECTMap.CMType.EVIDENCE.name());
    }
}

