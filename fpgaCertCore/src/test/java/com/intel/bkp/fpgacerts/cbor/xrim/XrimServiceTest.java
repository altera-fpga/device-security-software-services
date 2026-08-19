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

package com.intel.bkp.fpgacerts.cbor.xrim;

import ch.qos.logback.classic.Level;
import com.intel.bkp.fpgacerts.cbor.exception.CborParserException;
import com.intel.bkp.fpgacerts.cbor.exception.XrimVerificationException;
import com.intel.bkp.fpgacerts.cbor.rim.RimUnsigned;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimUnsignedParser;
import com.intel.bkp.fpgacerts.cbor.signer.CborSignatureVerifier;
import com.intel.bkp.fpgacerts.dp.DistributionPointConnector;
import com.intel.bkp.test.KeyGenUtils;
import com.intel.bkp.test.LoggerTestUtil;
import com.intel.bkp.test.rim.RimGenerator;
import com.intel.bkp.test.rim.XrimGenerator;
import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.test.RandomUtils.generateRandomHex;
import static com.intel.bkp.test.rim.RimGenerator.DP_URL;
import static com.intel.bkp.test.rim.RimGenerator.MANIFEST_ID_LEN;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class XrimServiceTest {

    private static final String DENY_MANIFEST_KEY_ID = "51ac25b8dc58405cb4c94772120ba68a";
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
    private static final KeyPair KEY_PAIR = KeyGenUtils.genEc384();
    private static final RimUnsigned UNSIGNED_RIM = RimGenerator.instance()
        .publicKey(KEY_PAIR.getPublic())
        .manifestId(generateRandomHex(MANIFEST_ID_LEN))
        .generateUnsignedEntity();
    private static final boolean ALLOW_UNSIGNED = true;
    private static final boolean RESTRICT_UNSIGNED = false;

    private LoggerTestUtil loggerTestUtil;

    @Mock
    private DistributionPointConnector dpConnector;

    @Mock
    private CborSignatureVerifier cborSignatureVerifier;

    @InjectMocks
    private XrimService sut;

    @BeforeEach
    void setup() {
        loggerTestUtil = LoggerTestUtil.instance(sut.getClass());
    }

    private static byte[] generateUnsignedRim(boolean designRim,
                                              boolean newCorimFormat,
                                              boolean includeProfile) {
        final byte[] unsigned = RimGenerator.instance()
            .signed(false)
            .design(designRim)
            .newCorimFormat(newCorimFormat)
            .issuerKeyId(issuerKeyId)
            .expectedDigest0(digest0)
            .expectedDigest1(digest1)
            .expectedDigest2(digest2)
            .layer0Digest(layer0Digest)
            .layer1Digest(layer1Digest)
            .includeProfile(includeProfile)
            .generate();
        return unsigned;
    }

    @Test
    void verifyXRimAndEnsureRimIsNotRevoked_NewCorimFormat_Passed() {
        // given
        final RimUnsigned unsignedRim = RimUnsignedParser.instance().parse(generateUnsignedRim(false, true, false));

        // when-then
        assertDoesNotThrow(
            () -> sut.verifyXRimAndEnsureRimIsNotRevoked(unsignedRim, KEY_PAIR.getPublic(), RESTRICT_UNSIGNED)
        );
    }

    @Test
    void verifyXRimAndEnsureRimIsNotRevoked_WithRestrictedUnsigned_WithNotRevoked_Success() {
        // given
        final byte[] xrimResponse = XrimGenerator.instance().keyPair(KEY_PAIR).generate();
        mockDistributionPointResult(xrimResponse);
        mockSignatureVerification(true);

        // when-then
        assertDoesNotThrow(
            () -> sut.verifyXRimAndEnsureRimIsNotRevoked(UNSIGNED_RIM, KEY_PAIR.getPublic(), RESTRICT_UNSIGNED)
        );
    }

    @Test
    void verifyXRimAndEnsureRimIsNotRevoked_WithAllowedUnsigned_WithUnsignedXCoRim_WithNotRevoked_Success() {
        // given
        final byte[] xrimResponse = XrimGenerator.instance()
            .signed(false)
            .denyItemId(DENY_MANIFEST_KEY_ID)
            .generate();
        mockDistributionPointResult(xrimResponse);

        // when-then
        assertDoesNotThrow(
            () -> sut.verifyXRimAndEnsureRimIsNotRevoked(UNSIGNED_RIM, KEY_PAIR.getPublic(), ALLOW_UNSIGNED)
        );
    }

    @Test
    void verifyXRimAndEnsureRimIsNotRevoked_WithRestrictedUnsigned_WithUnsignedXCoRim_WithNotRevoked_ThrowsException() {
        // given
        final byte[] xrimResponse = XrimGenerator.instance()
            .signed(false)
            .denyItemId(DENY_MANIFEST_KEY_ID)
            .generate();
        mockDistributionPointResult(xrimResponse);

        // when-then
        final var ex = assertThrows(XrimVerificationException.class,
            () -> sut.verifyXRimAndEnsureRimIsNotRevoked(UNSIGNED_RIM, KEY_PAIR.getPublic(), RESTRICT_UNSIGNED));

        // then
        assertEquals("XCoRIM verification failed: XCoRIM not signed. Signature cannot be verified.",
            ex.getMessage());
    }

    @Test
    void verifyXRimAndEnsureRimIsNotRevoked_WithRestrictedUnsigned_WithUnsignedXCoRim_WithRevoked_ThrowsException() {
        // given
        final byte[] xrimResponse = XrimGenerator.instance()
            .signed(false)
            .denyItemId(UNSIGNED_RIM.getManifestId())
            .generate();
        mockDistributionPointResult(xrimResponse);

        // when-then
        final var ex = assertThrows(XrimVerificationException.class,
            () -> sut.verifyXRimAndEnsureRimIsNotRevoked(UNSIGNED_RIM, KEY_PAIR.getPublic(), ALLOW_UNSIGNED));

        // then
        assertEquals("XCoRIM verification failed: provided CoRIM is revoked.", ex.getMessage());
    }

    @Test
    void verifyXRimAndEnsureRimIsNotRevoked_WithRestrictedUnsigned_WithNotValidSignature_ThrowsException() {
        // given
        final byte[] xrimResponse = XrimGenerator.instance().keyPair(KEY_PAIR).generate();
        mockDistributionPointResult(xrimResponse);
        mockSignatureVerification(false);

        // when-then
        final var ex = assertThrows(XrimVerificationException.class,
            () -> sut.verifyXRimAndEnsureRimIsNotRevoked(UNSIGNED_RIM, KEY_PAIR.getPublic(), RESTRICT_UNSIGNED));

        // then
        assertEquals("XCoRIM verification failed: invalid signature.", ex.getMessage());
    }

    @Test
    void verifyXRimAndEnsureRimIsNotRevoked_WithRestrictedUnsigned_WithNoPublicKey_ThrowsException() {
        // given
        final byte[] xrimResponse = XrimGenerator.instance().keyPair(KEY_PAIR).generate();
        mockDistributionPointResult(xrimResponse);

        // when-then
        final var ex = assertThrows(XrimVerificationException.class,
            () -> sut.verifyXRimAndEnsureRimIsNotRevoked(UNSIGNED_RIM, null, RESTRICT_UNSIGNED));

        // then
        assertEquals("XCoRIM verification failed: invalid signature.", ex.getMessage());
    }

    @Test
    void verifyXRimAndEnsureRimIsNotRevoked_WithRestrictedUnsigned_WithRevoked_ThrowsException() {
        // given
        final byte[] xrimResponse = XrimGenerator.instance()
            .keyPair(KEY_PAIR)
            .denyItemId(UNSIGNED_RIM.getManifestId())
            .generate();
        mockDistributionPointResult(xrimResponse);
        mockSignatureVerification(true);

        // when-then
        final var ex = assertThrows(XrimVerificationException.class,
            () -> sut.verifyXRimAndEnsureRimIsNotRevoked(UNSIGNED_RIM, KEY_PAIR.getPublic(), RESTRICT_UNSIGNED));

        // then
        assertEquals("XCoRIM verification failed: provided CoRIM is revoked.", ex.getMessage());
    }

    @Test
    void verifyXRimAndEnsureRimIsNotRevoked_WithRestrictedUnsigned_WithNoXrimLocator_ThrowsException() {
        // given
        final RimUnsigned unsignedRim = RimUnsignedParser.instance().parse(generateUnsignedRim(false, false, true));

        // when-then
        final var ex = assertThrows(XrimVerificationException.class,
            () -> sut.verifyXRimAndEnsureRimIsNotRevoked(unsignedRim, KEY_PAIR.getPublic(), RESTRICT_UNSIGNED));

        // then
        assertEquals("XCoRIM verification failed: unable to find XCoRIM locator in provided CoRIM file.",
            ex.getMessage());
    }

    @Test
    void verifyXRimAndEnsureRimIsNotRevoked_WithAllowedUnsigned_WithNoXrimLocator_LogsSkipped() {
        // given
        final RimUnsigned unsignedRim = RimUnsignedParser.instance().parse(generateUnsignedRim(false, false, true));

        // when-then
        assertDoesNotThrow(
            () -> sut.verifyXRimAndEnsureRimIsNotRevoked(unsignedRim, KEY_PAIR.getPublic(), ALLOW_UNSIGNED)
        );

        // then
        assertTrue(loggerTestUtil.contains("CER locator not found. Verification of XCoRIM [Skipped]", Level.INFO));
    }

    @Test
    void verifyXRimAndEnsureRimIsNotRevoked_WithRestrictedUnsigned_WithNotCborObjectOnDp_ThrowsException() {
        // given
        mockDistributionPointResult(null);

        // when-then
        final var ex = assertThrows(XrimVerificationException.class,
            () -> sut.verifyXRimAndEnsureRimIsNotRevoked(UNSIGNED_RIM, KEY_PAIR.getPublic(), RESTRICT_UNSIGNED));

        // then
        assertTrue(
            ex.getMessage().contains("XCoRIM verification failed: unable to download or parse XCoRIM from path:")
        );
    }

    @Test
    void verifyXRimAndEnsureRimIsNotRevoked_WithRestrictedUnsigned_WithNotXCoRimContent_ThrowsException() {
        // given
        final byte[] xrimResponse = new byte[]{1, 2, 3};
        mockDistributionPointResult(xrimResponse);

        // when-then
        final var ex = assertThrows(CborParserException.class,
            () -> sut.verifyXRimAndEnsureRimIsNotRevoked(UNSIGNED_RIM, KEY_PAIR.getPublic(), RESTRICT_UNSIGNED));

        // then
        assertEquals("Unexpected CoRIM/XCoRIM outer tag.", ex.getMessage());
    }

    private void mockDistributionPointResult(byte[] response) {
        when(dpConnector.tryGetBytes(anyString())).thenReturn(Optional.ofNullable(response));
    }

    private void mockSignatureVerification(boolean valid) {
        when(cborSignatureVerifier.verify(any(PublicKey.class), any(CBORObject.class))).thenReturn(valid);
    }
}
