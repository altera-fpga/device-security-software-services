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

package com.intel.bkp.bkps.rest.user.service;

import com.intel.bkp.bkps.domain.AppUser;
import com.intel.bkp.bkps.domain.DynamicCertificate;
import com.intel.bkp.bkps.exception.X509TrustManagerException;
import com.intel.bkp.bkps.repository.DynamicCertificateRepository;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.security.X509TrustManagerManager;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.test.CertificateUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Optional;

import static com.intel.bkp.crypto.x509.utils.X509CertificateUtils.toPem;
import static com.intel.bkp.test.AssertionUtils.verifyExpectedErrorCode;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class DynamicCertificateServiceTest {

    @Mock
    private X509TrustManagerManager x509TrustManagerFactory;

    @Mock
    private DynamicCertificateRepository dynamicCertificateRepository;

    @InjectMocks
    private DynamicCertificateService sut;

    private static final String TEST_FINGERPRINT = "testFingerprint";
    private static final String TEST_ALIAS = "testAlias";

    @Test
    void saveCertificateData_Success() throws Exception {
        // given
        final X509Certificate certificate = CertificateUtils.generateCertificate();
        final String fingerprint = CryptoUtils.generateFingerprint(certificate.getEncoded());
        final String certificateEncoded = toPem(certificate);

        // when
        sut.saveCertificateData(certificateEncoded, fingerprint, null, TEST_ALIAS);

        // then
        verify(x509TrustManagerFactory).addEntry(any(X509Certificate.class), anyString());
    }

    @Test
    void saveCertificateData_WithErrorInAddingToTruststore_ThrowsException() throws Exception {
        // given
        final X509Certificate certificate = CertificateUtils.generateCertificate();
        final String fingerprint = CryptoUtils.generateFingerprint(certificate.getEncoded());
        final String certificateEncoded = toPem(certificate);

        doThrow(X509TrustManagerException.class)
            .when(x509TrustManagerFactory).addEntry(any(X509Certificate.class), anyString());

        // when
        final BKPInternalServerException exception = assertThrows(BKPInternalServerException.class,
            () -> sut.saveCertificateData(certificateEncoded, fingerprint, null, TEST_ALIAS)
        );

        // then
        verify(x509TrustManagerFactory).addEntry(any(X509Certificate.class), anyString());
        verifyExpectedErrorCode(exception, ErrorCodeMap.SAVE_CERTIFICATE_IN_TRUSTSTORE_FAILED);
    }

    @Test
    void fingerprintExists_ReturnsTrue() {
        // given
        when(dynamicCertificateRepository.existsByFingerprint(TEST_FINGERPRINT)).thenReturn(true);

        // when
        final boolean actual = sut.fingerprintExists(TEST_FINGERPRINT);

        // then
        assertTrue(actual);
    }

    @Test
    void fingerprintExists_ReturnsFalse() {
        // given
        when(dynamicCertificateRepository.existsByFingerprint(TEST_FINGERPRINT)).thenReturn(false);

        // when
        final boolean actual = sut.fingerprintExists(TEST_FINGERPRINT);

        // then
        assertFalse(actual);
    }

    @Test
    void verifyNotExistInTruststore_Verified() throws Exception {
        // given
        final X509Certificate certificate = CertificateUtils.generateCertificate();
        final String certificateEncoded = toPem(certificate);
        when(x509TrustManagerFactory.fingerprintExists(anyString()))
            .thenReturn(false);

        // when
        sut.verifyNotExistInTruststore(certificateEncoded);

        // then
        verify(x509TrustManagerFactory).fingerprintExists(anyString());
    }

    @Test
    void verifyNotExistInTruststore_WithExistingFingerprint_ThrowsException() throws Exception {
        // given
        final X509Certificate certificate = CertificateUtils.generateCertificate();
        final String certificateEncoded = toPem(certificate);
        when(x509TrustManagerFactory.fingerprintExists(anyString()))
            .thenReturn(true);

        // when
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.verifyNotExistInTruststore(certificateEncoded)
        );

        // then
        verify(x509TrustManagerFactory).fingerprintExists(anyString());
        verifyExpectedErrorCode(exception, ErrorCodeMap.CERTIFICATE_FINGERPRINT_EXISTS);
    }

    @Test
    void verifyNotExistInTruststore_WithExceptionFromTrustManager_ThrowsException() throws Exception {
        // given
        final X509Certificate certificate = CertificateUtils.generateCertificate();
        final String certificateEncoded = toPem(certificate);
        when(x509TrustManagerFactory.fingerprintExists(anyString()))
            .thenThrow(X509TrustManagerException.class);

        // when
        final BKPInternalServerException exception = assertThrows(BKPInternalServerException.class,
            () -> sut.verifyNotExistInTruststore(certificateEncoded)
        );

        // then
        verify(x509TrustManagerFactory).fingerprintExists(anyString());
        verifyExpectedErrorCode(exception, ErrorCodeMap.CERTIFICATE_IN_TRUSTSTORE_CHECK_FAILED);
    }

    @Test
    void deleteDynamicCertForUser_ReturnsTrue() throws Exception {
        // given
        AppUser appUser = prepareAppUser();
        mockDynamicCertificate(false);

        // when
        sut.deleteDynamicCertForUser(appUser);

        // then
        verify(dynamicCertificateRepository).save(any(DynamicCertificate.class));
    }

    @Test
    void deleteDynamicCertForUser_WithErrorOnRemovingCertificate_ReturnsTrue() throws Exception {
        // given
        AppUser appUser = prepareAppUser();
        mockDynamicCertificate(true);

        // when
        sut.deleteDynamicCertForUser(appUser);

        // then
        verify(dynamicCertificateRepository).save(any(DynamicCertificate.class));
    }

    private AppUser prepareAppUser() {
        AppUser appUser = new AppUser();
        appUser.setFingerprint(TEST_FINGERPRINT);
        return appUser;
    }

    private void mockDynamicCertificate(boolean throwException) throws Exception {
        DynamicCertificate existingCertificate = DynamicCertificate
            .createUserCert("alias", "fingerprint", Instant.now(), "certificatePem");
        when(dynamicCertificateRepository.findByFingerprint(anyString()))
            .thenReturn(Optional.of(existingCertificate));

        if (!throwException) {
            when(x509TrustManagerFactory.exists(anyString())).thenReturn(true);
        } else {
            when(x509TrustManagerFactory.exists(anyString())).thenThrow(new X509TrustManagerException(""));
        }
    }
}
