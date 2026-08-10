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

package com.intel.bkp.bkps.utils;

import com.intel.bkp.bkps.exception.CertificateChainValidationFailed;
import com.intel.bkp.bkps.exception.CertificateManagerException;
import com.intel.bkp.bkps.exception.CertificateWrongFormat;
import com.intel.bkp.bkps.exception.MissingLeafCertificate;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.test.CertificateUtils;
import com.intel.bkp.test.X509GeneratorUtil;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import static com.intel.bkp.crypto.x509.utils.X509CertificateUtils.toPem;
import static com.intel.bkp.test.AssertionUtils.verifyExpectedErrorCode;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
public class CertificateManagerTest {

    private static X509Certificate leafCertificate;
    private static byte[] chainCertificateBytes;

    private CertificateManager sut;

    @BeforeAll
    static void beforeClass() throws Exception {
        X509GeneratorUtil x509GeneratorUtil = new X509GeneratorUtil();
        chainCertificateBytes = x509GeneratorUtil.generateX509Chain().getBytes();
        leafCertificate = x509GeneratorUtil.getLeafCertificate();
    }

    @BeforeEach
    void setUp() {
        this.sut = new CertificateManager();
    }

    @Test
    void getCertificateContent_Success() {
        //when
        final byte[] bytesFromCertificate = CertificateManager.getCertificateContent(leafCertificate);

        //then
        assertNotNull(bytesFromCertificate);
    }

    @Test
    void getCertificateContent_ThrowsException() throws CertificateEncodingException {
        // given
        X509Certificate mock = Mockito.mock(X509Certificate.class);
        Mockito.when(mock.getEncoded()).thenThrow(CertificateEncodingException.class);
        //when
        assertThrows(CertificateChainValidationFailed.class, () -> CertificateManager.getCertificateContent(mock));
    }

    @Test
    void parseChain_ThrowsException() {
        //when
        assertThrows(CertificateWrongFormat.class, () -> sut.parseChain("TESTCHAIN".getBytes()));
    }

    @Test
    void getCertificates_Success() throws Exception {
        //when
        sut.parseChain(chainCertificateBytes);
        final List<X509Certificate> certificateChainListFromBytes = sut.getCertificates();

        //then
        assertNotNull(certificateChainListFromBytes);
        assertEquals(3, certificateChainListFromBytes.size());
        X509Certificate child = certificateChainListFromBytes.get(0);
        X509Certificate parent = certificateChainListFromBytes.get(1);
        child.verify(parent.getPublicKey());
    }

    @Test
    void verifyParentsInChainByPubKey_Success() {
        //given
        sut.parseChain(chainCertificateBytes);

        //when
        sut.verifyParentsInChainByPubKey();
    }

    @Test
    void verifyParentsInChainByPubKey_WithWrongParent_ThrowsException() {
        //given
        sut.parseChain(chainCertificateBytes);
        final List<X509Certificate> tempParsedList = sut.getCertificates();
        Collections.reverse(tempParsedList);
        sut.setCertificates(tempParsedList);

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.verifyParentsInChainByPubKey()
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.PARENT_CERTIFICATES_DO_NOT_MATCH);
    }

    @Test
    void verifyChainListSize_Success() {
        //given
        sut.parseChain(chainCertificateBytes);

        //when
        sut.verifyChainListSize();
    }

    @Test
    void verifyChainListSize_ThrowsException() {
        // when-then
        final CertificateManagerException exception = assertThrows(CertificateManagerException.class,
            () -> sut.verifyChainListSize()
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.CERTIFICATE_CHAIN_WRONG_SIZE);
    }

    @Test
    void getLeafCertificate_Success() {
        //given
        sut.parseChain(chainCertificateBytes);

        //when
        final X509Certificate leafCertificate = sut.getLeafCertificate();

        //then
        final String expected = DigestUtils.sha256Hex(CertificateManager.getCertificateContent(leafCertificate));
        final String actual = DigestUtils.sha256Hex(
            CertificateManager.getCertificateContent(CertificateManagerTest.leafCertificate)
        );

        assertEquals(expected, actual);
    }

    @Test
    void getLeafCertificate_ThrowsException() {
        //when
        assertThrows(MissingLeafCertificate.class, () -> sut.getLeafCertificate());
    }

    @Test
    void getCertificateFingerprint_Success() throws Exception {
        // given
        final X509Certificate certificate = CertificateUtils.generateCertificate();
        final String certificateInPem = toPem(certificate);
        // when
        final String fingerprint = CertificateManager.getCertificateFingerprint(certificateInPem);
        // then
        assertEquals(CryptoUtils.generateFingerprint(certificate.getEncoded()), fingerprint);
    }
}
