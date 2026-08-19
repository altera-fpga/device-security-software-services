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

package com.intel.bkp.fpgacerts.cbor.service;

import com.intel.bkp.fpgacerts.cbor.CborBroker;
import com.intel.bkp.fpgacerts.cbor.CborConverter;
import com.intel.bkp.fpgacerts.cbor.CborObjectParser;
import com.intel.bkp.fpgacerts.cbor.LocatorTreeNodeMockedFields;
import com.intel.bkp.fpgacerts.cbor.LocatorType;
import com.intel.bkp.fpgacerts.cbor.LocatorsTreeNode;
import com.intel.bkp.fpgacerts.cbor.exception.RimVerificationException;
import com.intel.bkp.fpgacerts.cbor.rim.Comid;
import com.intel.bkp.fpgacerts.cbor.rim.RimSigned;
import com.intel.bkp.fpgacerts.cbor.rim.RimUnsigned;
import com.intel.bkp.fpgacerts.cbor.rim.comid.Claims;
import com.intel.bkp.fpgacerts.cbor.rim.comid.EnvironmentMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ReferenceTriple;
import com.intel.bkp.fpgacerts.cbor.rim.comid.mapping.ReferenceTripleToTcbInfoMeasurementMapper;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimSignedParser;
import com.intel.bkp.fpgacerts.cbor.signer.CborSignatureVerifier;
import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.fpgacerts.cbor.utils.ProfileValidator;
import com.intel.bkp.fpgacerts.cbor.utils.SignatureTimeValidator;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimService;
import com.intel.bkp.fpgacerts.dice.tcbinfo.MeasurementHolder;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoKey;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import com.intel.bkp.fpgacerts.dp.DistributionPointConnector;
import com.intel.bkp.fpgacerts.ect.ECTMap;
import com.intel.bkp.fpgacerts.ect.ElementMap;
import com.intel.bkp.fpgacerts.ect.IECTMapStorage;
import com.intel.bkp.fpgacerts.url.FetchDataSchemeBroker;
import com.intel.bkp.test.rim.OneKeyGenerator;
import com.intel.bkp.test.rim.RimGenerator;
import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.intel.bkp.fpgacerts.cbor.service.CoRimHandler.MAX_NESTED_LOCATORS_DEPTH;
import static com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId.ECDSA_384;
import static com.intel.bkp.test.RandomUtils.generateRandomHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.matches;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CoRimHandlerTest {

    private static final String CERTIFICATE_PATH_REGEX = "http://localhost:9090/content/IPCS/rims/agilex_L1_.*\\.corim";
    private final List<String> trustedRootHash = List.of("35E08599DD52CB7533764DEE65C915BBAFD0E35E6252BCCD77F3A694390F618B");
    private static CborKeyPair signingKey;
    private ReferenceTripleToTcbInfoMeasurementMapper measurementMapper = spy(new ReferenceTripleToTcbInfoMeasurementMapper());
    private static final String issuerKeyId = generateRandomHex(RimGenerator.ISSUER_KEY_LEN);
    private static final String digest0 = generateRandomHex(48);
    private static final String digest1 = generateRandomHex(48);
    private static final String digest2 = generateRandomHex(48);
    private static final String layer0Digest = generateRandomHex(96);
    private static final String layer1Digest = generateRandomHex(48);

    @Mock
    private TcbInfoMeasurement tcbInfoMeasurement;

    @Mock
    private DistributionPointConnector distributionPointConnector;

    @Mock
    private RimSigningChainService chainService;

    @Mock
    private CborSignatureVerifier cborSignatureVerifier;

    @Mock
    private XrimService xrimService;

    @Mock
    private CborConverter cborConverter;

    @Mock
    private RimSignedParser rimSignedParser;

    @Mock
    private CborObjectParser cborObjectParser;

    @Mock
    private CBORObject cborA, cborB, cborC, cborD, cborE, cborF, cborG, cborD1, cborD2, cborD3;

    private CoRimHandler sut;

    private static CBORObject generateRim(boolean signing,
                                          boolean designRim,
                                          boolean newCorimFormat) {
        final byte[] rim = RimGenerator.instance()
            .signed(signing)
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
            .generate();
        return CborObjectParser.instance().parse(rim);
    }

    @BeforeEach
    void setUp() throws Exception {
        sut = new CoRimHandler(measurementMapper, chainService, cborSignatureVerifier, xrimService, false,
            distributionPointConnector, trustedRootHash);
        signingKey = OneKeyGenerator.generate(ECDSA_384);
    }

    @Test
    void getFormatName_Success() {
        //when-then
        assertEquals("CBOR CoRIM", sut.getFormatName());
    }

    @Test
    void getMeasurements_WithNewCorimFormat_Success() {
        // given
        final var signedFirmwareNewCorim = generateRim(true, false, true);
        when(chainService.verifyRimSigningChainAndGetRimSigningKey(any(String.class)))
            .thenReturn(signingKey.getPublicKey());
        when(cborSignatureVerifier.verify(signingKey.getPublicKey(), signedFirmwareNewCorim)).thenReturn(true);


        // when
        var result = sut.getMeasurements(signedFirmwareNewCorim);

        // then
        verifyRvList(result.getReferenceMeasurements().get(0),
                    "",
                    "intel.com",
                    "Agilex",
                    0,
                    0,
                    layer0Digest,
                    ECTMap.CMType.REFERENCE_VALUES.name());
        verifyRvList(result.getReferenceMeasurements().get(1),
                    "",
                    "intel.com",
                    "Agilex",
                    1,
                    0,
                    layer1Digest,
                    ECTMap.CMType.REFERENCE_VALUES.name());
        assertEquals(2, result.getConditionalEndorsedMeasurements().get(0).getCondition().toArray().length);
        verifyCondition(result.getConditionalEndorsedMeasurements().get(0).getCondition().get(0),
            "",
            "intel.com",
            "Agilex",
            0,
            0,
            layer0Digest);
        verifyCondition(result.getConditionalEndorsedMeasurements().get(0).getCondition().get(1),
            "",
            "intel.com",
            "Agilex",
            1,
            0,
            layer1Digest);
        assertEquals(1, result.getConditionalEndorsedMeasurements().get(0).getAddition().toArray().length);
        verifyAddition(result.getConditionalEndorsedMeasurements().get(0).getAddition().get(0),
            "111(h'6086480186F84D010F048148')",
            "intel.com",
            "Agilex",
            1,
            0,
            layer1Digest,
            ECTMap.CMType.ENDORSEMENTS.name());

    }

    @Test
    void getMeasurements_Success() {
        // given
        final var signedFirmwareOldCorim = generateRim(true, false, false);
        when(chainService.verifyRimSigningChainAndGetRimSigningKey(any(String.class)))
            .thenReturn(signingKey.getPublicKey());
        when(cborSignatureVerifier.verify(signingKey.getPublicKey(), signedFirmwareOldCorim)).thenReturn(true);


        // when
        var result = sut.getMeasurements(signedFirmwareOldCorim);

        // then
        assertEquals(2, result.getReferenceMeasurements().toArray().length);
        verifyRvList(result.getReferenceMeasurements().get(0),
            "",
            "intel.com",
            "Agilex",
            0,
            0,
            layer0Digest,
            ECTMap.CMType.REFERENCE_VALUES.name());
        verifyRvList(result.getReferenceMeasurements().get(1),
            "",
            "intel.com",
            "Agilex",
            1,
            0,
            layer1Digest,
            ECTMap.CMType.REFERENCE_VALUES.name());
        assertEquals(1, result.getConditionalEndorsedMeasurements().toArray().length);
        assertEquals(2, result.getConditionalEndorsedMeasurements().get(0).getCondition().toArray().length);
        verifyCondition(result.getConditionalEndorsedMeasurements().get(0).getCondition().get(0),
            "",
            "intel.com",
            "Agilex",
            0,
            0,
            layer0Digest);
        verifyCondition(result.getConditionalEndorsedMeasurements().get(0).getCondition().get(1),
            "",
            "intel.com",
            "Agilex",
            1,
            0,
            layer1Digest);
        assertEquals(1, result.getConditionalEndorsedMeasurements().get(0).getAddition().toArray().length);
        verifyAddition(result.getConditionalEndorsedMeasurements().get(0).getAddition().get(0),
            "111(h'6086480186F84D010F048148')",
            "intel.com",
            "Agilex",
            1,
            0,
            layer1Digest,
            ECTMap.CMType.ENDORSEMENTS.name());

    }

    @Test
    void getMeasurements_WithDesignRim_WithNewCorimFormat_Success() {
        // given
        final var signedDesignNewCorim = generateRim(true, true, true);
        final var signedFirmwareNewCorim = generateRim(true, false, true);
        when(chainService.verifyRimSigningChainAndGetRimSigningKey(any(String.class)))
            .thenReturn(signingKey.getPublicKey());
        when(cborSignatureVerifier.verify(signingKey.getPublicKey(), signedDesignNewCorim)).thenReturn(true);
        when(cborSignatureVerifier.verify(signingKey.getPublicKey(), CborObjectParser.instance().parse(signedFirmwareNewCorim)))
            .thenReturn(true);
        when(distributionPointConnector.tryGetBytes(matches(CERTIFICATE_PATH_REGEX)))
            .thenReturn(Optional.of(signedFirmwareNewCorim.EncodeToBytes()));

        // when
        var result = toOneList(sut.getMeasurements(signedDesignNewCorim));

        // then
        assertEquals(9, result.size());
    }

    @Test
    void getMeasurements_WithDesignRim_Success() {
        // given
        final var signedDesignOldCorim = generateRim(true, true, false);
        final var signedFirmwareOldCorim = generateRim(true, false, false);
        when(chainService.verifyRimSigningChainAndGetRimSigningKey(any(String.class)))
            .thenReturn(signingKey.getPublicKey());
        when(cborSignatureVerifier.verify(signingKey.getPublicKey(), signedDesignOldCorim)).thenReturn(true);
        when(cborSignatureVerifier.verify(signingKey.getPublicKey(), CborObjectParser.instance().parse(signedFirmwareOldCorim)))
            .thenReturn(true);
        when(distributionPointConnector.tryGetBytes(matches(CERTIFICATE_PATH_REGEX)))
            .thenReturn(Optional.of(signedFirmwareOldCorim.EncodeToBytes()));

        // when
        var result = toOneList(sut.getMeasurements(signedDesignOldCorim));

        // then
        assertEquals(9, result.size());
    }

    @Test
    void getMeasurements_WithDesignRim_WithMissingRimOnDp_ThrowsException() {
        // given
        final var signedDesignOldCorim = generateRim(true, true, false);
        when(chainService.verifyRimSigningChainAndGetRimSigningKey(any(String.class)))
            .thenReturn(signingKey.getPublicKey());
        when(cborSignatureVerifier.verify(signingKey.getPublicKey(), signedDesignOldCorim)).thenReturn(true);
        when(distributionPointConnector.tryGetBytes(matches(CERTIFICATE_PATH_REGEX)))
            .thenReturn(Optional.empty());

        // when-then
        final var ex = assertThrows(RimVerificationException.class, () -> sut.getMeasurements(signedDesignOldCorim));

        // then
        assertTrue(ex.getMessage().contains("CoRIM verification failed: failed to download data from path:"));
    }

    @Test
    void getMeasurements_WithUnsignedRim_IsUnsignedSupportedTrue_Success() {
        // given
        final var unsignedFirmwareOldCorim = generateRim(false, false, false);

        // when
        final var sutWithUnsignedSupport =
            sut = new CoRimHandler(measurementMapper, chainService, cborSignatureVerifier, xrimService, true,
                distributionPointConnector, trustedRootHash);
        final var result = sutWithUnsignedSupport.getMeasurements(unsignedFirmwareOldCorim);

        // then
        verify(cborSignatureVerifier, never()).verify(any(), (CBORObject) any());
        assertEquals(2, result.getReferenceMeasurements().toArray().length);
        verifyRvList(result.getReferenceMeasurements().get(0),
            "",
            "intel.com",
            "Agilex",
            0,
            0,
            layer0Digest,
            ECTMap.CMType.REFERENCE_VALUES.name());
        verifyRvList(result.getReferenceMeasurements().get(1),
            "",
            "intel.com",
            "Agilex",
            1,
            0,
            layer1Digest,
            ECTMap.CMType.REFERENCE_VALUES.name());
        assertEquals(1, result.getConditionalEndorsedMeasurements().toArray().length);
        assertEquals(2, result.getConditionalEndorsedMeasurements().get(0).getCondition().toArray().length);
        verifyCondition(result.getConditionalEndorsedMeasurements().get(0).getCondition().get(0),
            "",
            "intel.com",
            "Agilex",
            0,
            0,
            layer0Digest);
        verifyCondition(result.getConditionalEndorsedMeasurements().get(0).getCondition().get(1),
            "",
            "intel.com",
            "Agilex",
            1,
            0,
            layer1Digest);
        assertEquals(1, result.getConditionalEndorsedMeasurements().get(0).getAddition().toArray().length);
        verifyAddition(result.getConditionalEndorsedMeasurements().get(0).getAddition().get(0),
            "111(h'6086480186F84D010F048148')",
            "intel.com",
            "Agilex",
            1,
            0,
            layer1Digest,
            ECTMap.CMType.ENDORSEMENTS.name());
    }

    @Test
    void getMeasurements_WithUnsignedRim_IsUnsignedSupportedFalse_Throws() {
        // given
        final var unsignedFirmwareOldCorim = generateRim(false, false, false);

        // when-then
        final var ex = assertThrows(RimVerificationException.class, () -> sut.getMeasurements(unsignedFirmwareOldCorim));

        // then
        verify(cborSignatureVerifier, never()).verify(any(), (CBORObject) any());
        assertEquals("CoRIM verification failed: CoRIM not signed. Signature cannot be verified.", ex.getMessage());
    }

    @Test
    void getMeasurements_WithSignatureVerificationFailure_Throws() {
        // given
        final var signedFirmwareOldCorim = generateRim(true, false, false);
        when(chainService.verifyRimSigningChainAndGetRimSigningKey(any(String.class)))
            .thenReturn(signingKey.getPublicKey());
        when(cborSignatureVerifier.verify(signingKey.getPublicKey(), signedFirmwareOldCorim)).thenReturn(false);

        // when-then
        final var ex = assertThrows(RimVerificationException.class, () -> sut.getMeasurements(signedFirmwareOldCorim));

        // then
        assertEquals("CoRIM verification failed: invalid signature.", ex.getMessage());
    }

    @Test
    void getMeasurements_WithExpiredSignatureFailure_Throws() throws Exception {
        // given
        final CborKeyPair pair = OneKeyGenerator.generate(ECDSA_384);
        final byte[] signed = RimGenerator
            .instance()
            .privateKey(pair.getPrivateKey())
            .publicKey(pair.getPublicKey())
            .expired(true)
            .generate();

        final var cbor = CborObjectParser.instance().parse(signed);

        // when-then
        final var ex = assertThrows(RimVerificationException.class, () -> sut.getMeasurements(cbor));

        // then
        assertTrue(ex.getMessage().contains("CoRIM verification failed: signature expired at:"));
    }

    @Test
    void getMeasurements_WithLocatorsTree_Success() {
        // given
        when(chainService.verifyRimSigningChainAndGetRimSigningKey(any(String.class)))
            .thenReturn(signingKey.getPublicKey());

        try (var cborBrokerMockedStatic = mockStatic(CborBroker.class);
             var signatureTimeValidatorMockedStatic = mockStatic(SignatureTimeValidator.class);
             var profileValidatorMockedStatic = mockStatic(ProfileValidator.class);
             var fetchDataSchemeBrokerMockedStatic = mockStatic(FetchDataSchemeBroker.class);
             var cborObjectParserMockedStatic = mockStatic(CborObjectParser.class)) {
            final List<LocatorsTreeNode> nodeList = mockRimWithLocatorsTree();

            nodeList.stream().skip(1).forEach(node -> mockCborObjectParser(node.getObject(), node.getLink()));

            Mockito.doReturn(rimSignedParser).when(cborConverter).getParser();
            nodeList.forEach(node -> mockSingleNode(node.getObject(), node.getMocks().measurement(),
                node.getMocks().triple(), node.getMocks().comid(), node.getMocks().claims(),
                node.getMocks().rimUnsigned(), node.getMocks().rimSigned(), node.getChildren()));

            // when
            sut = new CoRimHandler(measurementMapper, chainService, cborSignatureVerifier, xrimService, false,
                distributionPointConnector, trustedRootHash);
            final var result = sut.getMeasurements(cborA);

            // then
            List<TcbInfoMeasurement> measurements = nodeList.stream().map(node -> node.getMocks().measurement()).toList();
            final var expectedRvList = ECTMap.createRvECTMap(measurements, trustedRootHash);
            assertEquals(expectedRvList.toString(), result.getReferenceMeasurements().toString());
            assertIterableEquals(emptyList(), result.getConditionalEndorsedMeasurements());
        }
    }

    @Test
    void getMeasurements_WithMaxDepth_Success() {
        // given
        when(chainService.verifyRimSigningChainAndGetRimSigningKey(any(String.class)))
            .thenReturn(signingKey.getPublicKey());

        try (var cborBrokerMockedStatic = mockStatic(CborBroker.class);
             var signatureTimeValidatorMockedStatic = mockStatic(SignatureTimeValidator.class);
             var profileValidatorMockedStatic = mockStatic(ProfileValidator.class);
             var fetchDataSchemeBrokerMockedStatic = mockStatic(FetchDataSchemeBroker.class);
             var cborObjectParserMockedStatic = mockStatic(CborObjectParser.class)) {

            final var lastNode = new LocatorsTreeNode(cborB, generateInternalMocks(), "B");
            final var nodeList = mockRimWithMaxDepth(lastNode);
            mockCborObjectParser(lastNode.getObject(), lastNode.getLink());

            nodeList.stream().skip(1).forEach(node -> mockCborObjectParser(node.getObject(), node.getLink()));

            Mockito.doReturn(rimSignedParser).when(cborConverter).getParser();
            nodeList.forEach(node -> mockSingleNode(node.getObject(), node.getMocks().measurement(),
                node.getMocks().triple(), node.getMocks().comid(), node.getMocks().claims(),
                node.getMocks().rimUnsigned(), node.getMocks().rimSigned(), node.getChildren()));

            // when
            sut = new CoRimHandler(measurementMapper, chainService, cborSignatureVerifier, xrimService, false,
                distributionPointConnector, trustedRootHash);
            final var result = sut.getMeasurements(cborA);

            // then
            List<TcbInfoMeasurement> measurements = nodeList.stream().map(node -> node.getMocks().measurement()).toList();
            final var expectedRvList = ECTMap.createRvECTMap(measurements, trustedRootHash);
            assertEquals(expectedRvList.toString(), result.getReferenceMeasurements().toString());
            assertFalse(result.getReferenceMeasurements().contains(lastNode.getMocks().measurement()));
            assertIterableEquals(emptyList(), result.getConditionalEndorsedMeasurements());
        }
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
        assertTrue(condition.getAuthority().isEmpty());
        assertTrue(condition.getCmtype().isEmpty());
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

    private List<ECTMap> toOneList(MeasurementHolder holder) {
        final List<ECTMap> rvList = holder.getReferenceMeasurements().stream()
                                .map(IECTMapStorage::getAddition)
                                .flatMap(List::stream)
                                .collect(Collectors.toList());
        final List<ECTMap> evList = holder.getConditionalEndorsedMeasurements().stream()
                                .map(IECTMapStorage::getAddition)
                                .flatMap(List::stream)
                                .collect(Collectors.toList());
        return Stream.of(rvList, evList)
                .flatMap(List::stream)
                .collect(Collectors.toList());
    }

    /*  Structure of locators:

                           A
                         /   \
                        B      C
                       / \     / \
                     D    E   F   G
                  /  |  \
                 D1  D2  D3
    */
    private List<LocatorsTreeNode> mockRimWithLocatorsTree() {
        LocatorsTreeNode nodeA =
            new LocatorsTreeNode(cborA, generateInternalMocks(), "A");

        LocatorsTreeNode nodeC = nodeA.addChild(cborC, generateInternalMocks(), "C");

        LocatorsTreeNode nodeF = nodeC.addChild(cborF, generateInternalMocks(), "F");
        LocatorsTreeNode nodeG = nodeC.addChild(cborG, generateInternalMocks(), "G");

        LocatorsTreeNode nodeB = nodeA.addChild(cborB, generateInternalMocks(), "B");
        LocatorsTreeNode nodeE = nodeB.addChild(cborE, generateInternalMocks(), "E");
        LocatorsTreeNode nodeD = nodeB.addChild(cborD, generateInternalMocks(), "D");

        LocatorsTreeNode nodeD1 = nodeD.addChild(cborD1, generateInternalMocks(), "D1");
        LocatorsTreeNode nodeD2 = nodeD.addChild(cborD2, generateInternalMocks(), "D2");
        LocatorsTreeNode nodeD3 = nodeD.addChild(cborD3, generateInternalMocks(), "D3");

        return Arrays.asList(nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeD1, nodeD2, nodeD3);
    }

    /*  Structure of locators:

                       A
                       |
                       1
                       |
                      ...
                       |
                       15
                       |
                       B
    */
    private List<LocatorsTreeNode> mockRimWithMaxDepth(LocatorsTreeNode lastNode) {
        final var rootNode = new LocatorsTreeNode(cborA, generateInternalMocks() , "A");

        final var locatorsTree = new ArrayList<LocatorsTreeNode>();
        locatorsTree.add(rootNode);
        LocatorsTreeNode currentNode = rootNode;

        for (int i = 0; i < MAX_NESTED_LOCATORS_DEPTH; i++) {
            currentNode = currentNode.addChild(mock(CBORObject.class), generateInternalMocks(), Integer.toString(i));
            locatorsTree.add(currentNode);
        }
        currentNode.addChild(lastNode);
        return locatorsTree;
    }

    private void mockSingleNode(CBORObject cbor, TcbInfoMeasurement tim, ReferenceTriple referenceTriple, Comid comid,
                                Claims claims, RimUnsigned rimUnsigned, RimSigned rimSigned,
                                List<LocatorsTreeNode> children) {
        when(CborBroker.detectCborType(cbor)).thenReturn(cborConverter);
        final List<Comid> listOfComids = new ArrayList<>();
        final List<ReferenceTriple> referenceTriples = new ArrayList<>();

        when(rimSignedParser.parse(cbor)).thenReturn(rimSigned);
        when(rimSigned.getPayload()).thenReturn(rimUnsigned);

        when(rimUnsigned.getLocatorLink(LocatorType.CER)).thenReturn(Optional.of(""));
        listOfComids.add(comid);
        when(rimUnsigned.getComIds()).thenReturn(listOfComids);
        when(comid.getClaims()).thenReturn(claims);

        referenceTriples.add(referenceTriple);
        when(claims.getReferenceTriples()).thenReturn(referenceTriples);
        doReturn(tim).when(measurementMapper).map(referenceTriple);

        final var locatorList = children.stream().map(
            LocatorsTreeNode::getLink).toList();
        when(rimUnsigned.getLocatorLinks(LocatorType.CORIM)).thenReturn(locatorList);

        when(cborSignatureVerifier.verify(signingKey.getPublicKey(), cbor)).thenReturn(true);
        when(tim.getKey()).thenReturn(TcbInfoKey.builder().build());
        when(tim.getValue()).thenReturn(TcbInfoValue.builder().build());
    }

    private void mockCborObjectParser(CBORObject cbor, String link) {
        when(CborObjectParser.instance()).thenReturn(cborObjectParser);
        when(cborObjectParser.parse(link.getBytes())).thenReturn(cbor);
        when(FetchDataSchemeBroker.fetchData(link, distributionPointConnector))
            .thenReturn(Optional.of(link.getBytes()));
    }

    private LocatorTreeNodeMockedFields generateInternalMocks() {
        return new LocatorTreeNodeMockedFields(mock(TcbInfoMeasurement.class),
            mock(ReferenceTriple.class), mock(Comid.class), mock(Claims.class), mock(RimSigned.class),
            mock(RimUnsigned.class));
    }
}
