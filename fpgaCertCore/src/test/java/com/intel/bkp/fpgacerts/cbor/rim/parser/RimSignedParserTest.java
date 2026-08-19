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

package com.intel.bkp.fpgacerts.cbor.rim.parser;

import com.intel.bkp.crypto.curve.CurvePoint;
import com.intel.bkp.fpgacerts.cbor.LocatorItem;
import com.intel.bkp.fpgacerts.cbor.LocatorType;
import com.intel.bkp.fpgacerts.cbor.rim.Comid;
import com.intel.bkp.fpgacerts.cbor.rim.ProtectedMetaMap;
import com.intel.bkp.fpgacerts.cbor.rim.ProtectedSignersItem;
import com.intel.bkp.fpgacerts.cbor.rim.RimProtectedHeader;
import com.intel.bkp.fpgacerts.cbor.rim.RimUnsigned;
import com.intel.bkp.fpgacerts.cbor.rim.comid.Claims;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ComidEntity;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ComidId;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ConditionalEndorsedTriple;
import com.intel.bkp.fpgacerts.cbor.rim.comid.EnvironmentMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ReferenceTriple;
import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.fpgacerts.utils.SkiHelper;
import com.intel.bkp.test.rim.OneKeyGenerator;
import com.intel.bkp.test.rim.RimGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId.ECDSA_384;
import static com.intel.bkp.test.rim.ComidBuilderUtils.environmentMap;
import static com.intel.bkp.test.rim.ComidBuilderUtils.measurementMap;
import static com.intel.bkp.test.rim.ComidBuilderUtils.versionMap;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static org.junit.jupiter.api.Assertions.assertEquals;

class RimSignedParserTest {

    private static CborKeyPair signingKey;
    private static final String issuerKeyId = "66273F6BE6F8AD62668E676877E035B23495EE08";
    private static final String digest0 = "C8E658DF2AA43CE3FE6011C9E0B5595C0ADC07FA5742BAFC14D715403B17CA55A4C15EE6B368"
                                            + "DBC473ED9098A97A8CE5";
    private static final String digest1 = "637293C2FDADC183C0593C0333768BA5738EBB4AF4E12A5E501A9692BCF32950DC960F1B15DA"
                                            + "4D4B9710E4C677075C08";
    private static final String digest2 = "33DFE9033F9F8069AA2ECEB3555694D4C0C096F6D95084C27976E449750B385B93538F623B06"
                                            + "993B1C5C3733C1E87EA8";
    private static final String layer0Digest = "62B5B4E8690F14CB3F5846CD29B350680800DA6880FDD558983B3B31FEFC73ECED1324A"
                                                + "F54E3C3711EF2786B33507414C066C61648898F04837B3FFFD58905ED";
    private static final String layer1Digest = "E55C006CAA9D792E020012D4CDA5A31A2BE259271F01A088287AD070F7A5FFBF5AEA613"
                                                + "F21FA657D4ED2AA07E601E707";
    private static final List<String> profile = List.of("6086480186F84D010F06");

    private static byte[] generateSignedRim(boolean designRim,
                                            boolean newCorimFormat,
                                            boolean includeProfile) {
        final byte[] signed = RimGenerator.instance()
            .design(designRim)
            .privateKey(signingKey.getPrivateKey())
            .publicKey(signingKey.getPublicKey())
            .newCorimFormat(newCorimFormat)
            .issuerKeyId(issuerKeyId)
            .expectedDigest0(digest0)
            .expectedDigest1(digest1)
            .expectedDigest2(digest2)
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
    void parse_WithFirmwareRim_WithNewCorimFormat_Success() {
        // given
        final byte[] fwCoRIM = generateSignedRim(false, true, false);

        // when
        final var entity = RimSignedParser.instance().parse(fwCoRIM);

        // then
        assertEquals(getProtectedHeader().getMetaMap().getMetaItems(), entity.getProtectedData().getMetaMap().getMetaItems());
        assertEquals(getProtectedHeader().getAlgorithmId(), entity.getProtectedData().getAlgorithmId());
        assertEquals(getProtectedHeader().getContentType(), entity.getProtectedData().getContentType());
        assertEquals(getProtectedHeader().getIssuerKeyId(), entity.getProtectedData().getIssuerKeyId());
        assertEquals(getUnsignedFwRimData(true, false), entity.getPayload());
    }

    @Test
    void parse_WithDesignRim_WithNewCorimFormat_Success() {
        // given
        final byte[] designCoRIM = generateSignedRim(true, true, false);

        // when
        final var entity = RimSignedParser.instance().parse(designCoRIM);

        // then
        assertEquals(getProtectedHeader().getMetaMap().getMetaItems(), entity.getProtectedData().getMetaMap().getMetaItems());
        assertEquals(getProtectedHeader().getAlgorithmId(), entity.getProtectedData().getAlgorithmId());
        assertEquals(getProtectedHeader().getContentType(), entity.getProtectedData().getContentType());
        assertEquals(getProtectedHeader().getIssuerKeyId(), entity.getProtectedData().getIssuerKeyId());
        assertEquals(getUnsignedDesignRimData(true, false), entity.getPayload());
    }

    @Test
    void parse_WithFirmwareRim_WithOldCorimFormat_Success() {
        // given
        final byte[] fwCoRIM = generateSignedRim(false, false, true);

        // when
        final var entity = RimSignedParser.instance().parse(fwCoRIM);

        // then
        assertEquals(getProtectedHeader().getMetaMap().getMetaItems(), entity.getProtectedData().getMetaMap().getMetaItems());
        assertEquals(getProtectedHeader().getAlgorithmId(), entity.getProtectedData().getAlgorithmId());
        assertEquals(getProtectedHeader().getContentType(), entity.getProtectedData().getContentType());
        assertEquals(getProtectedHeader().getIssuerKeyId(), entity.getProtectedData().getIssuerKeyId());
        assertEquals(getUnsignedFwRimData(false, true), entity.getPayload());
    }

    @Test
    void parse_WithDesignRim_WithOldCorimFormat_Success() {
        // given
        final byte[] designCoRIM = generateSignedRim(true, false, true);

        // when
        final var entity = RimSignedParser.instance().parse(designCoRIM);

        // then
        assertEquals(getProtectedHeader().getMetaMap().getMetaItems(), entity.getProtectedData().getMetaMap().getMetaItems());
        assertEquals(getProtectedHeader().getAlgorithmId(), entity.getProtectedData().getAlgorithmId());
        assertEquals(getProtectedHeader().getContentType(), entity.getProtectedData().getContentType());
        assertEquals(getProtectedHeader().getIssuerKeyId(), entity.getProtectedData().getIssuerKeyId());
        assertEquals(getUnsignedDesignRimData(false, true), entity.getPayload());
    }

    private RimProtectedHeader getProtectedHeader() {
        return RimProtectedHeader.builder()
            .algorithmId(ECDSA_384)
            .contentType("application/rim+cbor")
            .issuerKeyId(issuerKeyId)
            .metaMap(ProtectedMetaMap.builder()
                .metaItems(List.of(
                    ProtectedSignersItem.builder()
                        .entityName("Firmware Author")
                        .build(),
                    ProtectedSignersItem.builder()
                        .entityName("CN=Intel:Agilex:ManSign")
                        .build()
                ))
                .build())
            .build();
    }

    private RimUnsigned getUnsignedFwRimData(boolean newCorimFormat, boolean includeProfile) {
        final List<ReferenceTriple> referenceTriples = List.of(
            ReferenceTriple.builder()
                .environmentMap(environmentMap("Agilex", 0, 0))
                .measurementMap(measurementMap(0, 7, layer0Digest))
                .build(),
            ReferenceTriple.builder()
                .environmentMap(environmentMap("Agilex", 1, 0))
                .measurementMap(measurementMap(0, 7, layer1Digest))
                .build()
        );

        String rimFileName = (newCorimFormat) ? "RIM_Signing_agilex_n1e4hB5RviCbCBGE_%s" : "RIM_Signing_agilex_%s";
        rimFileName = rimFileName.formatted(SkiHelper.getSkiInBase64UrlForUrl(CurvePoint.from(signingKey.getPublicKey()).getAlignedDataToSize()));
        return RimUnsigned.builder()
            .manifestId("51AC25B8DC58405CB4C94772120BA68A")
            .comIds(List.of(Comid.builder()
                .id(ComidId.builder().value("51F505F82911480B9F44B8A614FF2B18").build())
                .entities(List.of(
                    ComidEntity.builder()
                        .entityName("Firmware manifest")
                        .roles(List.of(0))
                        .build()
                ))
                .claims(Claims.builder()
                    .referenceTriples(referenceTriples)
                    .endorsedTriples(newCorimFormat ? null :List.of(ReferenceTriple.builder()
                            .environmentMap(environmentMap("6086480186F84D010F048148", 1))
                            .measurementMap(MeasurementMap.builder()
                                .version(MeasurementVersion.builder()
                                    .version("release-2023.28.1.1")
                                    .versionScheme("3")
                                    .build())
                                .build())
                            .build()))
                    .conditionalEndorsedTriples(newCorimFormat ? ConditionalEndorsedTriple.builder()
                        .conditions(referenceTriples)
                        .endorsements(List.of(ReferenceTriple.builder()
                            .environmentMap(environmentMap("6086480186F84D010F048148", 1))
                            .measurementMap(MeasurementMap.builder()
                                .version(MeasurementVersion.builder()
                                    .version("release-2023.28.1.1")
                                    .versionScheme("3")
                                    .build())
                                .build())
                            .build()))
                        .build() : null)
                    .build())
                .build()))
            .locators(List.of(
                new LocatorItem(LocatorType.CER,
                    "http://localhost:9090/content/IPCS/certs/%s.cer"
                        .formatted(rimFileName)),
                new LocatorItem(LocatorType.XCORIM,
                    "http://localhost:9090/content/IPCS/crls/%s.xcorim"
                        .formatted(rimFileName))
            ))
            .profile(includeProfile ? profile : List.of())
            .build();
    }

    private RimUnsigned getUnsignedDesignRimData(boolean newCorimFormat, boolean includeProfile) {
        final List<ReferenceTriple> referenceTriples = List.of(
            ReferenceTriple.builder()
                .environmentMap(environmentMap("6086480186F84D010F0401", 2))
                .measurementMap(measurementMap("0000000003000000", "FFFFFFFF000000FF"))
                .build(),
            ReferenceTriple.builder()
                .environmentMap(environmentMap("6086480186F84D010F0402", 2))
                .measurementMap(measurementMap(7, digest0)).build(),
            ReferenceTriple.builder()
                .environmentMap(environmentMap("6086480186F84D010F0403", 2))
                .measurementMap(measurementMap(7, digest1)).build(),
            ReferenceTriple.builder()
                .environmentMap(environmentMap("6086480186F84D010F0405", 2))
                .measurementMap(measurementMap(7, digest2)).build(),
            ReferenceTriple.builder()
                .environmentMap(environmentMap("6086480186F84D010F048148", 1))
                .measurementMap(versionMap("release-2021.3.4.2", "3"))
                .build()
        );

        String rimFileName = (newCorimFormat) ? "RIM_Signing_agilex_n1e4hB5RviCbCBGE_%s" : "RIM_Signing_agilex_%s";
        rimFileName = rimFileName.formatted(SkiHelper.getSkiInBase64UrlForUrl(CurvePoint.from(signingKey.getPublicKey()).getAlignedDataToSize()));
        return RimUnsigned.builder()
            .manifestId("51AC25B8DC58405CB4C94772120BA68A")
            .comIds(List.of(Comid.builder()
                .id(ComidId.builder().value("5CC21C1EDC37453D8FF559AFB335371C").build())
                .entities(List.of(
                    ComidEntity.builder()
                        .entityName("Design Author")
                        .regId("")
                        .roles(List.of(0))
                        .build()
                ))
                .claims(Claims.builder()
                    .referenceTriples(referenceTriples)
                    .endorsedTriples(newCorimFormat ? null : List.of(ReferenceTriple.builder()
                            .environmentMap(EnvironmentMap.builder()
                                .classId("6086480186F84D010F048149")
                                .vendor("intel.com")
                                .build())
                            .measurementMap(MeasurementMap.builder()
                                .version(MeasurementVersion.builder().version("").build())
                                .build())
                            .build()))
                    .conditionalEndorsedTriples(newCorimFormat ? ConditionalEndorsedTriple.builder()
                        .conditions(referenceTriples)
                        .endorsements(List.of(ReferenceTriple.builder()
                            .environmentMap(EnvironmentMap.builder()
                                .classId("6086480186F84D010F048149")
                                .vendor("intel.com")
                                .build())
                            .measurementMap(MeasurementMap.builder()
                                .version(MeasurementVersion.builder().version("").build())
                                .build())
                            .build()))
                        .build() : null)
                    .build())
                .build()))
            .locators(List.of(
                new LocatorItem(LocatorType.CER,
                    "http://localhost:9090/content/IPCS/certs/%s.cer"
                        .formatted(rimFileName)),
                new LocatorItem(LocatorType.XCORIM,
                    "http://localhost:9090/content/IPCS/crls/%s.xcorim"
                        .formatted(rimFileName)),
                new LocatorItem(LocatorType.CORIM,
                    "http://localhost:9090/content/IPCS/rims/agilex_L1_%s.corim"
                        .formatted(SkiHelper.getFwIdInBase64UrlForUrl(fromHex(layer1Digest))))))
            .profile(includeProfile ? profile : List.of())
            .build();
    }
}
