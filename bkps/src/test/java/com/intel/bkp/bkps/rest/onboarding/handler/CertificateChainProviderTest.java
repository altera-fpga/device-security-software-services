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

package com.intel.bkp.bkps.rest.onboarding.handler;

import ch.qos.logback.classic.Level;
import com.intel.bkp.bkps.ArrayEquator;
import com.intel.bkp.bkps.exception.SetAuthorityGenericException;
import com.intel.bkp.bkps.rest.onboarding.model.DeviceId;
import com.intel.bkp.bkps.rest.prefetching.service.ZipPrefetchRepositoryService;
import com.intel.bkp.bkps.rest.provisioning.utils.ZipUtil;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.crypto.exceptions.X509CertificateParsingException;
import com.intel.bkp.crypto.x509.parsing.X509CertificateParser;
import com.intel.bkp.crypto.x509.utils.KeyIdentifierUtils;
import com.intel.bkp.crypto.x509.validation.AuthorityKeyIdentifierVerifier;
import com.intel.bkp.fpgacerts.model.Family;
import com.intel.bkp.test.FileUtils;
import com.intel.bkp.test.LoggerTestUtil;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static java.util.Collections.emptyList;
import static org.apache.commons.collections4.CollectionUtils.isEqualCollection;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateChainProviderTest {

    private static final String TEST_PATH = "zip";
    private static final String ZIP_AGILEX_DEV_PATH = "DEV_34_0029842e27ca682f_vEmoW9hRWHY-tu9ni4AmAwd_sA0.zip";
    private static final byte[] ZIP_AGILEX_DEV = prepareAgilexZipFile();
    private static final DeviceId DEVICE_ID = DeviceId.instance(Family.AGILEX, "0102030405060708");
    private static final String MATCHING_ENROLLMENT_DEVICE_ID_SKI = "BC49A85BD85158763EB6EF678B802603077FB00D";
    private static final String NOT_MATCHING_ENROLLMENT_DEVICE_ID_SKI = "AABB";
    private static final String SVN = "01";

    @Mock
    private X509Certificate enrollmentCertFromDevice;

    @Mock
    private X509Certificate ipcsEnrollmentCertMock;

    @Mock
    private X509Certificate deviceIdCertMock;

    @SneakyThrows
    private static byte[] prepareAgilexZipFile() {
        return FileUtils.readFromResources(TEST_PATH, ZIP_AGILEX_DEV_PATH);
    }

    @Mock
    private ZipPrefetchRepositoryService prefetchRepositoryService;

    @Mock
    private AuthorityKeyIdentifierVerifier authorityKeyIdentifierVerifier;

    @InjectMocks
    private CertificateChainProvider sut;

    private LoggerTestUtil loggerTestUtil;

    @Test
    void isAvailable_ReturnsTrue() {
        // given
        when(prefetchRepositoryService.isZipPrefetched(DEVICE_ID)).thenReturn(true);

        // when
        final boolean result = sut.isAvailable(DEVICE_ID);

        // then
        assertTrue(result);
    }

    @Test
    void get_NoZipPresentInDb_ReturnsEmpty() {
        // given
        when(prefetchRepositoryService.find(DEVICE_ID)).thenReturn(Optional.empty());

        // when
        final Optional<List<byte[]>> certsOpt = sut.get(DEVICE_ID, PufType.EFUSE, SVN, enrollmentCertFromDevice,
            false);

        // then
        assertTrue(certsOpt.isEmpty());
    }

    @Test
    void get_WithZipAvailable_Svn00_ForEfuseDeviceId() {
        // given
        final var deviceIdFromZip = getDeviceIdFromZip();
        final var deviceIdFromZipSki = getRealSkiFromDeviceIdFromZip(deviceIdFromZip);
        when(prefetchRepositoryService.find(DEVICE_ID)).thenReturn(Optional.of(ZIP_AGILEX_DEV));
        try (var keyIdentifierUtilsStaticMock = mockStatic(KeyIdentifierUtils.class)) {
            when(KeyIdentifierUtils.getSubjectKeyIdentifier(enrollmentCertFromDevice))
                .thenReturn(fromHex(MATCHING_ENROLLMENT_DEVICE_ID_SKI));
            when(KeyIdentifierUtils.getSubjectKeyIdentifier(deviceIdFromZip))
                .thenReturn(deviceIdFromZipSki);

            // when
            final Optional<List<byte[]>> certsOpt = sut.get(DEVICE_ID, PufType.EFUSE, "00", enrollmentCertFromDevice,
                false);

            // then
            final List<byte[]> certs = certsOpt.orElseThrow();
            assertEquals(3, certs.size());
        }
    }

    @Test
    void get_WithZipAvailable_ForEnrollmentFlow_ThrowsEnrollmentNotPresent() {
        // given
        loggerTestUtil = LoggerTestUtil.instance(sut.getClass());
        final var deviceIdFromZip = getDeviceIdFromZip();
        final var deviceIdFromZipSki = getRealSkiFromDeviceIdFromZip(deviceIdFromZip);
        when(prefetchRepositoryService.find(DEVICE_ID)).thenReturn(Optional.of(ZIP_AGILEX_DEV));
        try (var keyIdentifierUtilsStaticMock = mockStatic(KeyIdentifierUtils.class)) {
            when(KeyIdentifierUtils.getSubjectKeyIdentifier(enrollmentCertFromDevice))
                .thenReturn(fromHex(NOT_MATCHING_ENROLLMENT_DEVICE_ID_SKI));
            when(KeyIdentifierUtils.getSubjectKeyIdentifier(deviceIdFromZip)).thenReturn(deviceIdFromZipSki);

            // when-then
            final SetAuthorityGenericException ex = assertThrows(SetAuthorityGenericException.class,
                () -> sut.get(DEVICE_ID, PufType.EFUSE, SVN, enrollmentCertFromDevice, false));

            assertEquals("IPCS Enrollment SVN cert is absent.", ex.getMessage());
            verifyLogExists("File not found in ZIP: efuse/enrollment_01.cer", Level.DEBUG);
        }
    }

    @SneakyThrows
    @Test
    void get_WithZipAvailable_ForEnrollmentFlow_MockWholeZip_SkiAkiMatch_Success() {
        // given
        final var expectedResult = Stream.of(
            "auth/DICE_RootCA.cer",
            "auth/IPCS_agilex.cer",
            "efuse/enrollment_01.cer",
            "ENROLLMENT_CERT_FROM_DEVICE")
            .map(String::getBytes)
            .toList();
        when(prefetchRepositoryService.find(DEVICE_ID)).thenReturn(Optional.of(ZIP_AGILEX_DEV));
        try (var keyIdentifierUtilsStaticMock = mockStatic(KeyIdentifierUtils.class);
             var zipUtilStaticMock = mockStatic(ZipUtil.class);
             var x509CertificateParserStaticMock = mockStatic(X509CertificateParser.class)) {
            mockWholeZip();
            when(enrollmentCertFromDevice.getEncoded()).thenReturn("ENROLLMENT_CERT_FROM_DEVICE".getBytes());

            when(authorityKeyIdentifierVerifier.verify(enrollmentCertFromDevice, ipcsEnrollmentCertMock))
                    .thenReturn(true);

            // when
            final var result = sut.get(DEVICE_ID, PufType.EFUSE, SVN, enrollmentCertFromDevice,
                false);

            // then
            assertTrue(isEqualCollection(expectedResult, result.orElse(emptyList()), new ArrayEquator()));
        }
    }

    @SneakyThrows
    @Test
    void get_WithZipAvailable_ForEnrollmentFlow_MockWholeZip_SkiAkiNotMatch_Throws() {
        // given
        final var expectedResult = Stream.of(
                        "auth/DICE_RootCA.cer",
                        "auth/IPCS_agilex.cer",
                        "efuse/enrollment_01.cer",
                        "ENROLLMENT_CERT_FROM_DEVICE")
                .map(String::getBytes)
                .toList();
        when(prefetchRepositoryService.find(DEVICE_ID)).thenReturn(Optional.of(ZIP_AGILEX_DEV));
        try (var keyIdentifierUtilsStaticMock = mockStatic(KeyIdentifierUtils.class);
             var zipUtilStaticMock = mockStatic(ZipUtil.class);
             var x509CertificateParserStaticMock = mockStatic(X509CertificateParser.class)) {
            mockWholeZip();

            when(authorityKeyIdentifierVerifier.verify(enrollmentCertFromDevice, ipcsEnrollmentCertMock))
                    .thenReturn(false);

            // when - then
            final var ex = assertThrows(SetAuthorityGenericException.class, () ->
                sut.get(DEVICE_ID, PufType.EFUSE, SVN, enrollmentCertFromDevice, false));
        }
    }

    private void mockWholeZip() throws X509CertificateParsingException, CertificateEncodingException {
        when(KeyIdentifierUtils.getSubjectKeyIdentifier(enrollmentCertFromDevice))
            .thenReturn(fromHex(NOT_MATCHING_ENROLLMENT_DEVICE_ID_SKI));
        when(KeyIdentifierUtils.getSubjectKeyIdentifier(deviceIdCertMock))
            .thenReturn(fromHex(MATCHING_ENROLLMENT_DEVICE_ID_SKI));
        mockExtractFromZip();
        when(X509CertificateParser.toX509Certificate("efuse/deviceid.cer".getBytes())).thenReturn(deviceIdCertMock);
        when(X509CertificateParser.toX509Certificate("efuse/enrollment_01.cer".getBytes()))
            .thenReturn(ipcsEnrollmentCertMock);
    }

    private void mockExtractFromZip() {
        final var listOfPaths = List.of(
        "auth/DICE_RootCA.cer",
        "auth/IPCS_agilex.cer",
        "efuse/iiduds.cer",
        "efuse/deviceid.cer",
        "efuse/enrollment_01.cer");

        listOfPaths.forEach(x -> when(ZipUtil.extractFileFromZip(ZIP_AGILEX_DEV, x))
            .thenReturn(Optional.of(x.getBytes())));
    }

    private byte[] getRealSkiFromDeviceIdFromZip(X509Certificate deviceIdCert) {
        return KeyIdentifierUtils.getSubjectKeyIdentifier(deviceIdCert);
    }

    @SneakyThrows
    private X509Certificate getDeviceIdFromZip() {
        final var deviceIdCertBytes = ZipUtil.extractFileFromZip(ZIP_AGILEX_DEV, "efuse/deviceid.cer")
            .orElse(new byte[0]);
        return X509CertificateParser.toX509Certificate(deviceIdCertBytes);
    }

    private void verifyLogExists(String log, Level level) {
        assertTrue(loggerTestUtil.contains(log, level));
    }
}

