/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2025 Altera Corporation. All Rights Reserved.
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

package com.intel.bkp.bkps.attestation;

import com.intel.bkp.bkps.attestation.mapping.CacheCertificateMapper;
import com.intel.bkp.bkps.config.ApplicationProperties;
import com.intel.bkp.bkps.connector.DpConnector;
import com.intel.bkp.bkps.rest.prefetching.service.CertificatePrefetchRepositoryService;
import com.intel.bkp.core.properties.DistributionPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CacheCertificateFetcherTest {

    @Mock
    private X509Certificate x509Cert;

    @Mock
    private CertificatePrefetchRepositoryService certPrefetchRepositoryService;

    @Mock
    private DpConnector dpConnector;

    private ApplicationProperties applicationProperties;

    private CacheCertificateFetcher sut;

    @BeforeEach
    void prepareSut() {
        when(certPrefetchRepositoryService.getMapper()).thenReturn(new CacheCertificateMapper());
        applicationProperties = spy(new ApplicationProperties());
        applicationProperties.setDistributionPoint(new DistributionPoint(
            "https://tsci.intel.com/",
            "content/IPCS/certs/",
            "content/IPCS/",
            null,
            null
        ));
        sut = new CacheCertificateFetcher(certPrefetchRepositoryService, dpConnector, applicationProperties);
    }

    @Test
    void isValid_WithCertCurrentlyValid_ReturnsTrue() throws Exception {
        // given
        doNothing().when(x509Cert).checkValidity();

        // when
        assertTrue(sut.isValid(x509Cert));
    }

    @Test
    void isValid_WithExpiredCert_ReturnsFalse() throws Exception {
        // given
        doThrow(new CertificateExpiredException()).when(x509Cert).checkValidity();

        // when
        assertFalse(sut.isValid(x509Cert));
    }

    @Test
    void isValid_WithNotYetValidCert_ReturnsFalse() throws Exception {
        // given
        doThrow(new CertificateNotYetValidException()).when(x509Cert).checkValidity();

        // when
        assertFalse(sut.isValid(x509Cert));
    }

    @Test
    void isValid_WithUnexpectedRuntimeException_Throws() throws Exception {
        // given
        final var expectedEx = new RuntimeException();
        doThrow(expectedEx).when(x509Cert).checkValidity();

        // when-then
        final var thrownEx = assertThrows(RuntimeException.class, () -> sut.isValid(x509Cert));

        // then
        assertEquals(expectedEx, thrownEx);
    }

    @Test
    void fetchCertificate_CallsBaseFetchMethod() {
        // given
        final String path = "https://somePath";
        final Optional<X509Certificate> expected = Optional.of(x509Cert);
        final var sutSpy = spy(sut);
        when(sutSpy.fetch(path)).thenReturn(expected);

        // when
        final var result = sutSpy.fetchCertificate(path);

        // then
        assertEquals(expected, result);
        verify(sutSpy).fetch(path);
    }
}
