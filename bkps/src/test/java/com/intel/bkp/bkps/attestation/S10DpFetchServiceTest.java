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

package com.intel.bkp.bkps.attestation;

import com.intel.bkp.bkps.config.ApplicationProperties;
import com.intel.bkp.bkps.exception.PrefetchingGenericException;
import com.intel.bkp.bkps.rest.prefetching.model.PrefetchChainDataDTO;
import com.intel.bkp.core.properties.DistributionPoint;
import com.intel.bkp.crypto.x509.utils.X509CertificateUtils;
import com.intel.bkp.test.FileUtils;
import lombok.SneakyThrows;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.toX509Certificate;
import static com.intel.bkp.crypto.x509.parsing.X509CrlParser.toX509Crl;
import static com.intel.bkp.fpgacerts.chain.DistributionPointCertificate.getX509Certificates;
import static com.intel.bkp.fpgacerts.chain.DistributionPointCrl.getX509Crls;
import static com.intel.bkp.test.DateTimeUtils.toInstant;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class S10DpFetchServiceTest {

    private static final String TEST_FOLDER = "certs/s10Chain/";
    private static final String DP_BASE_URL = "https://tsci.intel.com";
    private static final String DP_CERT_PATH = "content";
    private static final String DEVICE_ID_HEX = "8265302622187CD8";
    private static final Instant NOW_INSTANT = toInstant("2021-03-10T11:21:58");

    private static MockedStatic<Instant> instantMockStatic;
    private static X509Certificate attestationCert;
    private static X509Certificate ipcsSigningCaCert;
    private static X509Certificate ipcsRootCert;

    private static X509CRL ipcsSigningCaCrl;
    private static X509CRL ipcsRootCrl;

    @Mock
    private ApplicationProperties applicationProperties;

    @Mock
    private CacheCertificateFetcher certFetcher;

    @Mock
    private CacheCrlFetcher crlFetcher;

    @Mock
    private DistributionPoint distributionPoint;

    private S10DpFetchService sut;

    @BeforeAll
    static void init() throws Exception {
        attestationCert = toX509Certificate(getBytesFromFile("attestation_B96D93594B94FD12_00000002.cer"));
        ipcsSigningCaCert = toX509Certificate(getBytesFromFile("IPCS_stratix10.cer"));
        ipcsRootCert = toX509Certificate(getBytesFromFile("DICE_RootCA.cer"));

        ipcsSigningCaCrl = toX509Crl(getBytesFromFile("IPCS_stratix10.crl"));
        ipcsRootCrl = toX509Crl(getBytesFromFile("DICE.crl"));

        instantMockStatic = mockStatic(Instant.class, CALLS_REAL_METHODS);
        when(Instant.now()).thenReturn(NOW_INSTANT);
    }

    @AfterAll
    static void closeStaticMock() {
        instantMockStatic.close();
    }

    @BeforeEach
    void setUp() {
        when(applicationProperties.getDistributionPoint()).thenReturn(distributionPoint);
        when(distributionPoint.getMainPath()).thenReturn(DP_BASE_URL);
        when(distributionPoint.getAttestationCertBasePath()).thenReturn(DP_CERT_PATH);
        sut = new S10DpFetchService(applicationProperties, new CacheChainFetcher(certFetcher),
            new CacheCrlMapFetcher(crlFetcher));
    }

    @Test
    void fetch_WithValidFullChain_Success() {
        // given
        mockCertificates();
        mockCrls();

        final var expectedCerts = List.of(attestationCert, ipcsSigningCaCert, ipcsRootCert);
        final var expectedCrls = List.of(ipcsSigningCaCrl, ipcsRootCrl);
        final List<X509Certificate> expectedIidCerts = List.of();

        // when
        final PrefetchChainDataDTO result = sut.fetch(DEVICE_ID_HEX);

        // then
        verifyResult(expectedCerts, expectedCrls, expectedIidCerts, result);
    }

    @Test
    void fetch_WithNotSelfSignedRootCert_WithDownload_ThrowsException() {
        // given
        mockCertificates();

        // when-then
        try (var utils = mockStatic(X509CertificateUtils.class, CALLS_REAL_METHODS)) {
            utils.when(() -> X509CertificateUtils.isSelfSigned(any())).thenReturn(false);
            assertThrows(PrefetchingGenericException.class, () -> sut.fetch(DEVICE_ID_HEX));
        }

        // then
        verify(certFetcher).fetchCertificate(contains("attestation_8265302622187CD8_00000002.cer"));
        verify(certFetcher).fetchCertificate(contains("IPCS/certs/IPCS_stratix10.cer"));
        verify(certFetcher).fetchCertificate(contains("DICE/certs/DICE_RootCA.cer"));
    }

    private static byte[] getBytesFromFile(String filename) throws Exception {
        return FileUtils.readFromResources(TEST_FOLDER, filename);
    }

    private void mockCertificates() {
        mockCertificateExistence("attestation_8265302622187CD8_00000002.cer", attestationCert);
        mockCertificateExistence("IPCS/certs/IPCS_stratix10.cer", ipcsSigningCaCert);
        mockCertificateExistence("DICE/certs/DICE_RootCA.cer", ipcsRootCert);
    }

    @SneakyThrows
    private void mockCertificateExistence(String path, X509Certificate certificate) {
        when(certFetcher.fetchCertificate(contains(path)))
            .thenReturn(Optional.ofNullable(certificate));
    }

    private void mockCrls() {
        mockCrlExistence("IPCS/crls/IPCS_stratix10.crl", ipcsSigningCaCrl);
        mockCrlExistence("DICE/crls/DICE.crl", ipcsRootCrl);
    }

    @SneakyThrows
    private void mockCrlExistence(String path, X509CRL crl) {
        when(crlFetcher.fetch(contains(path)))
            .thenReturn(Optional.ofNullable(crl));
    }

    private void verifyResult(List<X509Certificate> expectedCerts, List<X509CRL> expectedCrls,
                              List<X509Certificate> expectedIidCerts, PrefetchChainDataDTO result) {
        assertIterableEquals(expectedCerts, getX509Certificates(result.getCertificates()));
        assertIterableEquals(expectedCrls, getX509Crls(result.getCrls()));
        assertIterableEquals(expectedIidCerts, getX509Certificates(result.getCertificatesIID()));
        verify(certFetcher, times(expectedCerts.size() + expectedIidCerts.size()))
            .fetchCertificate(anyString());
        verify(crlFetcher, times(expectedCrls.size())).fetch(anyString());
    }
}
