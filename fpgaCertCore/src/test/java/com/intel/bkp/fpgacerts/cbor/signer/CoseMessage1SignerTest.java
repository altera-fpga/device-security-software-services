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

package com.intel.bkp.fpgacerts.cbor.signer;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.curve.CurvePoint;
import com.intel.bkp.crypto.impl.EcUtils;
import com.intel.bkp.fpgacerts.cbor.LocatorItem;
import com.intel.bkp.fpgacerts.cbor.LocatorType;
import com.intel.bkp.fpgacerts.cbor.ProtectedHeaderType;
import com.intel.bkp.fpgacerts.cbor.rim.Comid;
import com.intel.bkp.fpgacerts.cbor.rim.ProtectedMetaMap;
import com.intel.bkp.fpgacerts.cbor.rim.ProtectedSignersItem;
import com.intel.bkp.fpgacerts.cbor.rim.RimProtectedHeader;
import com.intel.bkp.fpgacerts.cbor.rim.RimSigned;
import com.intel.bkp.fpgacerts.cbor.rim.RimUnsigned;
import com.intel.bkp.fpgacerts.cbor.rim.builder.RimUnsignedBuilder;
import com.intel.bkp.fpgacerts.cbor.rim.comid.Claims;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ComidEntity;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ComidId;
import com.intel.bkp.fpgacerts.cbor.rim.comid.Digest;
import com.intel.bkp.fpgacerts.cbor.rim.comid.EnvironmentMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ReferenceTriple;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimSignedParser;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimUnsignedParser;
import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId;
import com.intel.bkp.fpgacerts.cbor.utils.CborDateConverter;
import com.intel.bkp.fpgacerts.utils.SkiHelper;
import com.intel.bkp.test.FileUtils;
import com.intel.bkp.test.rim.OneKeyGenerator;
import com.intel.bkp.test.rim.RimGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.ArrayList;
import java.util.List;

import static com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId.ECDSA_384;
import static com.intel.bkp.test.FileUtils.TEST_FOLDER;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


class CoseMessage1SignerTest {

    private final CborSignatureVerifier cborSignatureVerifier = new CborSignatureVerifier();
    private static CborKeyPair signingKey;
    private static final String issuerKeyId = "537814DAAE4CADF98F3497CF9059FDF7FCC428E8";
    private static final String layer0Digest = "26B15D3C904B4FA7EB51D9CA40C06D6228B30E37C11BED342F62BEE3CAC0D7C059E33F0BDB21F930AB84F2BDB4F587C1";
    private static final String layer1Digest = "F2C9F87762366BF2E36ABDAFAD03A6BAECF2E2BF3C20BF00DB24106C6289475AA85B8B1A1197577B96CAE7CDE55FA88C";

    private static byte[] generateRim(boolean sign,
                                      boolean newCorimFormat) {
        final byte[] signed = RimGenerator.instance()
            .signed(sign)
            .distributionPointUrl("http://localhost:9090/content/IPCS")
            .privateKey(signingKey.getPrivateKey())
            .publicKey(signingKey.getPublicKey())
            .newCorimFormat(newCorimFormat)
            .issuerKeyId(issuerKeyId)
            .layer0Digest(layer0Digest)
            .layer1Digest(layer1Digest)
            .date(CborDateConverter.fromString("9999-12-31T23:59:59Z"))
            .generate();
        return signed;
    }

    @Test
    void sign_NewCorimFormat_WithGeneratedData_WithGeneratedSignature_Success() throws Exception {
        // given
        signingKey = getSigningKey();
        final byte[] rawData = FileUtils.readFromResources(TEST_FOLDER, "new_fw_rim_signed.rim");
        final RimSigned signedExpected = RimSignedParser.instance().parse(rawData);
        final byte[] payload = generateRim(false, true);
        final RimUnsigned unsignedActual = RimUnsignedParser.instance().parse(payload);
        final List<LocatorItem> locators = new ArrayList<>();
        final String ski = SkiHelper.getSkiInBase64UrlForUrl(CurvePoint
            .from(signingKey.getPublicKey())
            .getAlignedDataToSize());
        locators.add(new LocatorItem(LocatorType.CER,
            "http://localhost:9090/content/IPCS/certs/RIM_Signing_agilex_n1e4hB5RviCbCBGE_%s.cer".formatted(ski)));
        locators.add(new LocatorItem(LocatorType.XCORIM,
            "http://localhost:9090/content/IPCS/crls/RIM_Signing_agilex_n1e4hB5RviCbCBGE_%s.xcorim".formatted(ski)));

        unsignedActual.setLocators(locators);
        final RimProtectedHeader protectedHeader = prepareProtectedRimData(AlgorithmId.ECDSA_384);

        // when
        final byte[] signed = CoseMessage1Signer.instance().sign(
            signingKey,
            RimUnsignedBuilder.instance().build(unsignedActual),
            protectedHeader);
        final RimSigned signedActual = RimSignedParser.instance().parse(signed);

        // then
        assertTrue(cborSignatureVerifier.verify(signingKey.getPublicKey(), signed));
        compareParsedSignedData(signedExpected, signedActual);
        compareHexResultsWithoutSignature(rawData, signed);
    }

    @Test
    void sign_WithGeneratedData_WithGeneratedSignature_Success() throws Exception {
        // given
        signingKey = getSigningKey();
        final byte[] rawData = FileUtils.readFromResources(TEST_FOLDER, "fw_rim_signed.rim");
        final RimSigned signedExpected = RimSignedParser.instance().parse(rawData);

        final byte[] payload = prepareUnsignedRim();
        final RimProtectedHeader protectedHeader = prepareProtectedRimData(ECDSA_384);

        // when
        final byte[] signed = CoseMessage1Signer.instance().sign(signingKey, payload, protectedHeader);
        final RimSigned signedActual = RimSignedParser.instance().parse(signed);

        // then
        assertTrue(cborSignatureVerifier.verify(signingKey.getPublicKey(), signed));
        compareParsedSignedData(signedExpected, signedActual);
        compareHexResultsWithoutSignature(rawData, signed);
    }

    @ParameterizedTest
    @EnumSource(AlgorithmId.class)
    void sign_WithGeneratedKey_Success(AlgorithmId algorithmId) throws Exception {
        // given
        final byte[] rawData = FileUtils.readFromResources(TEST_FOLDER, "fw_rim_unsigned.rim");
        signingKey = OneKeyGenerator.generate(algorithmId);
        final RimUnsigned rimUnsigned = RimUnsignedParser.instance().parse(rawData);
        final byte[] payload = RimUnsignedBuilder.instance().build(rimUnsigned);
        final RimProtectedHeader protectedHeader = prepareProtectedRimData(algorithmId);

        // when
        final byte[] signed = CoseMessage1Signer.instance().sign(signingKey, payload, protectedHeader);

        // then
        assertTrue(cborSignatureVerifier.verify(signingKey.getPublicKey(), signed));
    }

    private static CborKeyPair getSigningKey() throws Exception {
        String privateKey = "008B3C43AC7741D04C6CE68B8B9DB555A5CBAF9DE4F8D9B73C0779396D748069AA7621100A7F34EA4C779FC8A306E94491";
        String publicKey = "9CC1A8B89D5F8BBCF8A81B5E352CA7EA41F4D90FCD6DAE3634DD2EDAEF7AD63B1B153D853112EEE9B532E3E84A8" +
            "CB11DE3F93D7BEDF37CB2DC44E3851428483BC31A04935E497C5D29AA5F0A7160000CDBAE5AB7B0DCE2070D0466B25EE27247";
        var priv = EcUtils.toPrivate(fromHex(privateKey), CryptoConstants.EC_KEY,
            CryptoConstants.EC_CURVE_SPEC_384, CryptoUtils.getBouncyCastleProvider());
        var pub = EcUtils.toPublic(fromHex(publicKey), CryptoConstants.EC_KEY,
            CryptoConstants.EC_CURVE_SPEC_384, CryptoUtils.getBouncyCastleProvider());
        return CborKeyPair.fromKeyPair(pub, priv);
    }

    private static RimProtectedHeader prepareProtectedRimData(AlgorithmId algorithmId) {
        return RimProtectedHeader.builder()
            .algorithmId(algorithmId)
            .contentType(ProtectedHeaderType.RIM.getContentType())
            .issuerKeyId(issuerKeyId)
            .metaMap(ProtectedMetaMap.builder()
                .metaItems(
                    List.of(ProtectedSignersItem.builder()
                            .entityName("Firmware Author")
                            .build(),
                        ProtectedSignersItem.builder()
                            .entityName("CN=Intel:Agilex:ManSign")
                            .build())
                )
                .signatureValidity(CborDateConverter.fromString("9999-12-31T23:59:59Z"))
                .build())
            .build();
    }

    private static byte[] prepareUnsignedRim() {
        final List<LocatorItem> locators = new ArrayList<>();
        locators.add(new LocatorItem(LocatorType.CER,
            "http://localhost:9090/content/IPCS/certs/RIM_Signing_agilex_KSLtPSpG-7483vkZorUBaH0ny_c.cer"));
        locators.add(new LocatorItem(LocatorType.XCORIM,
            "http://localhost:9090/content/IPCS/crls/RIM_Signing_agilex_KSLtPSpG-7483vkZorUBaH0ny_c.xcorim"));

        final var rimUnsignedGeneric = RimUnsigned.builder()
            .manifestId("51AC25B8DC58405CB4C94772120BA68A")
            .comIds(List.of(prepareComid()))
            .locators(locators)
            .profile(List.of("6086480186F84D010F06"))
            .build();
        return RimUnsignedBuilder.instance().build(rimUnsignedGeneric);
    }

    private static Comid prepareComid() {
        return Comid.builder()
            .id(ComidId.builder().value("51F505F82911480B9F44B8A614FF2B18").build())
            .entities(List.of(ComidEntity.builder()
                .entityName("Firmware manifest")
                .roles(List.of(0))
                .build()))
            .claims(Claims.builder()
                .referenceTriples(List.of(
                    ReferenceTriple.builder()
                        .environmentMap(EnvironmentMap.builder()
                            .vendor("intel.com")
                            .model("Agilex")
                            .layer(0)
                            .index(0)
                            .build())
                        .measurementMap(MeasurementMap.builder()
                            .svn(0)
                            .digests(List.of(Digest.builder()
                                .algorithm(7)
                                .value(layer0Digest)
                                .build()))
                            .build())
                        .build(),
                    ReferenceTriple.builder()
                        .environmentMap(EnvironmentMap.builder()
                            .vendor("intel.com")
                            .model("Agilex")
                            .layer(1)
                            .index(0)
                            .build())
                        .measurementMap(MeasurementMap.builder()
                            .svn(0)
                            .digests(List.of(Digest.builder()
                                .algorithm(7)
                                .value(layer1Digest)
                                .build()))
                            .build())
                        .build()))
                .endorsedTriples(List.of(ReferenceTriple.builder()
                    .environmentMap(EnvironmentMap.builder()
                        .classId("6086480186F84D010F048148")
                        .vendor("intel.com")
                        .layer(1)
                        .build())
                    .measurementMap(MeasurementMap.builder()
                        .version(MeasurementVersion.builder()
                            .version("release-2023.28.1.1")
                            .versionScheme("3")
                            .build())
                        .build())
                    .build()))
                .build())
            .build();
    }

    private static void compareParsedSignedData(RimSigned signedExpected, RimSigned signedActual) {
        assertEquals(signedExpected.getProtectedData().toString(), signedActual.getProtectedData().toString());
        assertEquals(signedExpected.getUnprotectedData(), signedActual.getUnprotectedData());
        assertEquals(signedExpected.getPayload(), signedActual.getPayload());
        assertNotEquals(signedExpected.getSignature(), signedActual.getSignature());
    }

    private static void compareHexResultsWithoutSignature(byte[] rawData, byte[] signed) {
        final String hexExpected = toHex(rawData);
        final String hexActual = toHex(signed);
        final int sha384SignatureLength = ECDSA_384.getSignatureLength() * 4;
        assertEquals(
            hexExpected.substring(0, hexExpected.length() - sha384SignatureLength),
            hexActual.substring(0, hexActual.length() - sha384SignatureLength)
        );
    }
}
