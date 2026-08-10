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
import com.intel.bkp.bkps.exception.PrefetchingFailedToDownloadException;
import com.intel.bkp.bkps.rest.prefetching.model.PrefetchChainDataDTO;
import com.intel.bkp.core.properties.DistributionPoint;
import com.intel.bkp.fpgacerts.dice.iidutils.IidFlowDetector;
import com.intel.bkp.test.FileUtils;
import lombok.SneakyThrows;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiceDpFetchServiceTest {

    private static final String TEST_FOLDER = "certs/diceChain/";
    private static final String DP_BASE_URL = "https://tsci.intel.com";
    private static final String DP_CERT_PATH = "content";
    private static final String DEVICE_ID_CERT_PATH = "deviceid_6bea383a72f2f614_tD8rHN5UUUDoLX90vxIPW1Tm5MI.cer";
    private static final String ENROLLMENT_CERT_PATH = "enrollment_6bea383a72f2f614_00_Xmn0KCWZRla14ZxytxA6soW0E44.cer";
    private static final String IID_CERT_PATH = "iiduds_6bea383a72f2f614_Xmn0KCWZRla14ZxytxA6soW0E44.cer";
    private static final Instant NOW_INSTANT = toInstant("2021-03-10T11:21:58");

    private static MockedStatic<Instant> instantMockStatic;

    private static X509Certificate enrollmentDeviceIdCert;

    private static X509Certificate deviceIdCert;
    private static X509Certificate productFamilyCert;
    private static X509Certificate rootCert;
    private static X509Certificate iidDeviceCert;
    private static X509Certificate enrollmentCert;

    private static X509CRL productFamilyCrl;
    private static X509CRL productFamilyL1Crl;
    private static X509CRL diceCrl;

    @Mock
    private ApplicationProperties applicationProperties;

    @Mock
    private CacheCertificateFetcher certFetcher;

    @Mock
    private CacheCrlFetcher crlFetcher;

    @Mock
    private DistributionPoint distributionPoint;

    @Mock
    private IidFlowDetector iidFlowDetector;

    private DiceDpFetchService sut;

    @BeforeAll
    static void init() throws Exception {
        deviceIdCert = toX509Certificate(getBytesFromFile("deviceid_08cbe74ddca0b53a_7eukZEEF-nzSZWoHQrqQf53ru9A.cer"));
        productFamilyCert = toX509Certificate(getBytesFromFile("IPCS_agilex.cer"));
        rootCert = toX509Certificate(getBytesFromFile("DICE_RootCA.cer"));
        iidDeviceCert = toX509Certificate(getBytesFromFile("iiduds_08cbe74ddca0b53a_7eukZEEF-nzSZWoHQrqQf53ru9A.cer"));
        enrollmentCert = toX509Certificate(getBytesFromFile("ipcs_enrolment.der"));
        productFamilyCrl = toX509Crl(getBytesFromFile("IPCS_agilex.crl"));
        diceCrl = toX509Crl(getBytesFromFile("DICE.crl"));
        productFamilyL1Crl = toX509Crl(getBytesFromFile("IPCS_agilex_L1.crl"));

        enrollmentDeviceIdCert = toX509Certificate(getBytesFromFile("deviceider_6bea383a72f2f614.cer"));

        instantMockStatic = mockStatic(Instant.class, CALLS_REAL_METHODS);
        when(Instant.now()).thenReturn(NOW_INSTANT);
    }

    @AfterAll
    static void closeStaticMock() {
        instantMockStatic.close();
    }

    @Test
    void fetch_WithValidFullChain_WithNotIIDFlow_Success() {
        // given
        sut = prepareSut();
        mockCertificates(false, false);
        mockCrls();

        final var expectedCerts = List.of(deviceIdCert, productFamilyCert, rootCert);
        final var expectedCrls = List.of(productFamilyCrl, diceCrl, productFamilyL1Crl);
        final List<X509Certificate> expectedIidCerts = List.of();

        // when
        final PrefetchChainDataDTO result = sut.fetch(enrollmentDeviceIdCert);

        // then
        verifyResult(expectedCerts, expectedCrls, expectedIidCerts, false, result);
    }

    @Test
    void fetch_WithValidFullChain_WithEnrollmentFlow_WithNotIIDFlow_Success() {
        // given
        sut = prepareSut();
        mockCertificates(true, false);
        mockCrls();

        final var expectedCerts = List.of(enrollmentCert, productFamilyCert, rootCert);
        final var expectedCrls = List.of(productFamilyCrl, diceCrl, productFamilyL1Crl);
        final List<X509Certificate> expectedIidCerts = List.of();

        // when
        final PrefetchChainDataDTO result = sut.fetch(enrollmentDeviceIdCert);

        // then
        verifyResult(expectedCerts, expectedCrls, expectedIidCerts, true, result);
    }

    @Test
    void fetch_WithValidFullChain_WithIIDFlow_Success() {
        // given
        sut = prepareSut();
        mockCertificates(false, true);
        mockCrls();

        final var expectedCerts = List.of(deviceIdCert, productFamilyCert, rootCert);
        final var expectedCrls = List.of(productFamilyCrl, diceCrl, productFamilyL1Crl);
        final var expectedIidCerts = List.of(iidDeviceCert, productFamilyCert, rootCert);

        // when
        final PrefetchChainDataDTO result = sut.fetch(enrollmentDeviceIdCert);

        // then
        verifyResult(expectedCerts, expectedCrls, expectedIidCerts, false, result);
    }

    @Test
    void fetch_WithValidFullChain_WithEnrollmentFlow_WithIIDFlow_Success() {
        // given
        sut = prepareSut();

        mockCertificates(true, true);
        mockCrls();

        final var expectedCerts = List.of(enrollmentCert, productFamilyCert, rootCert);
        final var expectedCrls = List.of(productFamilyCrl, diceCrl, productFamilyL1Crl);
        final List<X509Certificate> expectedIidCerts = List.of(iidDeviceCert, productFamilyCert, rootCert);

        // when
        final PrefetchChainDataDTO result = sut.fetch(enrollmentDeviceIdCert);

        // then
        assertIterableEquals(expectedCerts, getX509Certificates(result.getCertificates()));
        assertIterableEquals(expectedCrls, getX509Crls(result.getCrls()));
        assertIterableEquals(expectedIidCerts, getX509Certificates(result.getCertificatesIID()));
    }

    @Test
    void fetch_WithNoChainFetched_Throws() {
        // given
        sut = prepareSut();

        // when-then
        final var ex = assertThrows(PrefetchingFailedToDownloadException.class,
            () -> sut.fetch(enrollmentDeviceIdCert));
        assertEquals(ex.getMessage(), "Failed to download at least one full chain (EFUSE or IID UDS).");
    }

    @Test
    void fetch_WithOnlyEfuseChainFetched_DoesNotThrow() {
        // given
        sut = prepareSut();
        mockIsIidFlow(true);
        mockCertificateExistence(DEVICE_ID_CERT_PATH, null);
        mockCertificateExistence(ENROLLMENT_CERT_PATH, enrollmentCert);
        mockCertificateExistence(IID_CERT_PATH, null);
        mockIssuerCertificates();
        mockCrls();

        // when-then
        final PrefetchChainDataDTO result = assertDoesNotThrow(() -> sut.fetch(enrollmentDeviceIdCert));

        // then
        assertFalse(result.getCertificates().isEmpty());
        assertTrue(result.getCertificatesIID().isEmpty());
    }

    @Test
    void fetch_WithOnlyIidChainFetched_DoesNotThrow() {
        // given
        sut = prepareSut();
        mockIsIidFlow(true);
        mockCertificateExistence(DEVICE_ID_CERT_PATH, null);
        mockCertificateExistence(ENROLLMENT_CERT_PATH, null);
        mockCertificateExistence(IID_CERT_PATH, iidDeviceCert);
        mockIssuerCertificates();
        mockCrls();

        // when-then
        final PrefetchChainDataDTO result = assertDoesNotThrow(() -> sut.fetch(enrollmentDeviceIdCert));

        // then
        assertTrue(result.getCertificates().isEmpty());
        assertFalse(result.getCertificatesIID().isEmpty());
    }

    private static byte[] getBytesFromFile(String filename) throws Exception {
        return FileUtils.readFromResources(TEST_FOLDER, filename);
    }

    private DiceDpFetchService prepareSut() {
        when(applicationProperties.getDistributionPoint()).thenReturn(distributionPoint);
        when(distributionPoint.getMainPath()).thenReturn(DP_BASE_URL);
        when(distributionPoint.getAttestationCertBasePath()).thenReturn(DP_CERT_PATH);

        return new DiceDpFetchService(applicationProperties, new CacheChainFetcher(certFetcher), certFetcher,
            new CacheCrlMapFetcher(crlFetcher), iidFlowDetector);
    }

    private void mockCertificates(boolean isEnrollment, boolean isIid) {
        if (isEnrollment) {
            mockCertificateExistence(DEVICE_ID_CERT_PATH, null);
            mockCertificateExistence(ENROLLMENT_CERT_PATH, enrollmentCert);
        } else {
            mockCertificateExistence(DEVICE_ID_CERT_PATH, deviceIdCert);
        }

        mockIsIidFlow(isIid);
        if (isIid) {
            mockCertificateExistence(IID_CERT_PATH, iidDeviceCert);
        }

        mockIssuerCertificates();
    }

    private void mockIssuerCertificates() {
        mockCertificateExistence("IPCS/certs/IPCS_agilex.cer", productFamilyCert);
        mockCertificateExistence("DICE/certs/DICE_RootCA.cer", rootCert);
    }

    private void mockIsIidFlow(boolean isIid) {
        when(iidFlowDetector.isIidFlow(enrollmentDeviceIdCert)).thenReturn(isIid);
    }

    @SneakyThrows
    private void mockCertificateExistence(String path, X509Certificate certificate) {
        when(certFetcher.fetchCertificate(contains(path)))
            .thenReturn(Optional.ofNullable(certificate));

    }

    private void mockCrls() {
        mockCrlExistence("IPCS/crls/IPCS_agilex.crl", productFamilyCrl);
        mockCrlExistence("DICE/crls/DICE.crl", diceCrl);
        mockCrlExistence("IPCS/crls/IPCS_agilex_L1.crl", productFamilyL1Crl);
    }

    @SneakyThrows
    private void mockCrlExistence(String path, X509CRL crl) {
        when(crlFetcher.fetch(contains(path)))
            .thenReturn(Optional.ofNullable(crl));

    }

    private void verifyResult(List<X509Certificate> expectedCerts, List<X509CRL> expectedCrls,
                              List<X509Certificate> expectedIidCerts, boolean enrollmentFlow,
                              PrefetchChainDataDTO result) {
        assertIterableEquals(expectedCerts, getX509Certificates(result.getCertificates()));
        assertIterableEquals(expectedCrls, getX509Crls(result.getCrls()));
        assertIterableEquals(expectedIidCerts, getX509Certificates(result.getCertificatesIID()));
        verify(certFetcher, times((expectedCerts.size() + (enrollmentFlow ? 1 : 0)) + expectedIidCerts.size()))
            .fetchCertificate(anyString());
        verify(crlFetcher, times(expectedCrls.size())).fetch(anyString());
    }
}
