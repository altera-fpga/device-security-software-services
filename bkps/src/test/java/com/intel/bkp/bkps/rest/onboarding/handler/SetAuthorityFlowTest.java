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

import com.intel.bkp.bkps.exception.SetAuthorityGenericException;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.crypto.x509.parsing.X509CertificateParser;
import com.intel.bkp.crypto.x509.utils.KeyIdentifierUtils;
import com.intel.bkp.crypto.x509.validation.AuthorityKeyIdentifierVerifier;
import lombok.SneakyThrows;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SetAuthorityFlowTest {

    private final byte[] deviceIdCertBytes = new byte[0];

    @Mock
    private X509Certificate deviceIdCert;

    @Mock
    private X509Certificate enrollmentDeviceIdCert;

    private byte[] ipcsEnrollmentCertBytes = new byte[0];

    @Mock
    private X509Certificate ipcsEnrollmentCert;

    @Mock
    private AuthorityKeyIdentifierVerifier akiVerifier;

    @Mock
    private CertificatesFromZipPathsHolder certificatesFromZipPathsHolder;

    private static MockedStatic<X509CertificateParser> x509CertificateParserStaticMock;

    @BeforeAll
    static void prepareStaticMock() {
        x509CertificateParserStaticMock = mockStatic(X509CertificateParser.class);
    }

    @AfterAll
    static void closeStaticMock() {
        x509CertificateParserStaticMock.close();
    }

    @ParameterizedTest
    @ValueSource(booleans =  {true, false})
    void getSetAuthorityFlowStrategy_WithPufTypeIID_ReturnIID(boolean isForceEnrollment) {

        // when
        final var result = SetAuthorityFlow.getSetAuthorityFlowStrategy(PufType.IID,
            Optional.of(deviceIdCertBytes), enrollmentDeviceIdCert, Optional.of(ipcsEnrollmentCertBytes), "ANY",
            isForceEnrollment, akiVerifier, certificatesFromZipPathsHolder);

        // then
        assertEquals(SetAuthorityFlow.IID, result);
    }

    @ParameterizedTest
    @EnumSource(value = PufType.class, names = {"IIDUSER", "INTEL_USER"})
    void getSetAuthorityFlowStrategy_WithUnsupportedPufs_Throws(PufType pufType) {

        // when-then
        assertThrows(SetAuthorityGenericException.class, () -> SetAuthorityFlow.getSetAuthorityFlowStrategy(pufType,
            Optional.of(deviceIdCertBytes), enrollmentDeviceIdCert, Optional.of(ipcsEnrollmentCertBytes), "ANY",
            true, akiVerifier, certificatesFromZipPathsHolder));
    }

    @SneakyThrows
    @ParameterizedTest
    @EnumSource(value = PufType.class, names = {"INTEL", "EFUSE"})
    void getSetAuthorityFlowStrategy_Svn01_EnrollmentAkiSkiMatch_ReturnEnrollment(PufType pufType) {
        // given
        when(X509CertificateParser.toX509Certificate(ipcsEnrollmentCertBytes)).thenReturn(ipcsEnrollmentCert);
        when(akiVerifier.verify(enrollmentDeviceIdCert, ipcsEnrollmentCert)).thenReturn(true);

        // when
        final var result = SetAuthorityFlow.getSetAuthorityFlowStrategy(pufType,
            Optional.of(deviceIdCertBytes), enrollmentDeviceIdCert, Optional.of(ipcsEnrollmentCertBytes), "01",
            true, akiVerifier, certificatesFromZipPathsHolder);

        // then
        assertEquals(SetAuthorityFlow.ENROLLMENT, result);
    }

    @ParameterizedTest
    @EnumSource(value = PufType.class, names = {"INTEL", "EFUSE"})
    void getSetAuthorityFlowStrategy_Svn01_ipcsEnrollmentCertBytesNull_Throws(PufType pufType) {

        // when - then
        assertThrows(SetAuthorityGenericException.class, () -> SetAuthorityFlow.getSetAuthorityFlowStrategy(pufType,
            Optional.of(deviceIdCertBytes), enrollmentDeviceIdCert, Optional.empty(), "01",
            true, akiVerifier, certificatesFromZipPathsHolder));
    }

    @SneakyThrows
    @ParameterizedTest
    @EnumSource(value = PufType.class, names = {"INTEL", "EFUSE"})
    void getSetAuthorityFlowStrategy_Svn01_EnrollmentAkiSkiNotMatch_Throws(PufType pufType) {
        // given
        when(X509CertificateParser.toX509Certificate(ipcsEnrollmentCertBytes)).thenReturn(ipcsEnrollmentCert);
        when(akiVerifier.verify(enrollmentDeviceIdCert, ipcsEnrollmentCert)).thenReturn(false);

        // when-then
        assertThrows(SetAuthorityGenericException.class, () -> SetAuthorityFlow.getSetAuthorityFlowStrategy(pufType,
            Optional.of(deviceIdCertBytes), enrollmentDeviceIdCert, Optional.of(ipcsEnrollmentCertBytes), "01", true,
            akiVerifier, certificatesFromZipPathsHolder));
    }

    @SneakyThrows
    @ParameterizedTest
    @EnumSource(value = PufType.class, names = {"INTEL", "EFUSE"})
    void getSetAuthorityFlowStrategy_Svn00_ForceEnrollmentTrue_ReturnEnrollment(PufType pufType) {
        // given
        when(X509CertificateParser.toX509Certificate(ipcsEnrollmentCertBytes)).thenReturn(ipcsEnrollmentCert);
        when(akiVerifier.verify(enrollmentDeviceIdCert, ipcsEnrollmentCert)).thenReturn(true);

        // when
        final var result = SetAuthorityFlow.getSetAuthorityFlowStrategy(pufType,
            Optional.of(deviceIdCertBytes), enrollmentDeviceIdCert, Optional.of(ipcsEnrollmentCertBytes), "00", true,
            akiVerifier, certificatesFromZipPathsHolder);

        // then
        assertEquals(SetAuthorityFlow.ENROLLMENT, result);
    }

    @SneakyThrows
    @ParameterizedTest
    @EnumSource(value = PufType.class, names = {"INTEL", "EFUSE"})
    void getSetAuthorityFlowStrategy_Svn00_ForceEnrollmentFalse_ReturnDeviceId(PufType pufType) {
        // given
        try (var keyIdentifierUtilsMockedStatic = mockStatic(KeyIdentifierUtils.class)) {
            when(X509CertificateParser.toX509Certificate(ipcsEnrollmentCertBytes)).thenReturn(ipcsEnrollmentCert);
            when(X509CertificateParser.toX509Certificate(deviceIdCertBytes)).thenReturn(deviceIdCert);
            when(KeyIdentifierUtils.getSubjectKeyIdentifier(deviceIdCert)).thenReturn(new byte[]{1, 2, 3});
            when(KeyIdentifierUtils.getSubjectKeyIdentifier(enrollmentDeviceIdCert)).thenReturn(new byte[]{1, 2, 3});

            // when
            final var result = SetAuthorityFlow.getSetAuthorityFlowStrategy(pufType,
                Optional.of(deviceIdCertBytes), enrollmentDeviceIdCert, Optional.of(ipcsEnrollmentCertBytes), "00",
                false, akiVerifier, certificatesFromZipPathsHolder);

            // then
            assertEquals(SetAuthorityFlow.DEVICE_ID, result);
        }
    }

    @SneakyThrows
    @ParameterizedTest
    @EnumSource(value = PufType.class, names = {"INTEL", "EFUSE"})
    void getSetAuthorityFlowStrategy_Svn00_DeviceIdCertNull_ForceEnrollmentFalse_Throws(PufType pufType) {
        // given
        try (var keyIdentifierUtilsMockedStatic = mockStatic(KeyIdentifierUtils.class)) {
            when(X509CertificateParser.toX509Certificate(ipcsEnrollmentCertBytes)).thenReturn(ipcsEnrollmentCert);
            when(KeyIdentifierUtils.getSubjectKeyIdentifier(deviceIdCert)).thenReturn(new byte[]{1, 2, 3});
            when(KeyIdentifierUtils.getSubjectKeyIdentifier(enrollmentDeviceIdCert)).thenReturn(new byte[]{1, 2, 3});

            // when - then
            assertThrows(SetAuthorityGenericException.class, () -> SetAuthorityFlow.getSetAuthorityFlowStrategy(pufType,
                Optional.empty(), enrollmentDeviceIdCert, Optional.of(ipcsEnrollmentCertBytes), "00",
                false, akiVerifier, certificatesFromZipPathsHolder));
        }
    }

    @SneakyThrows
    @ParameterizedTest
    @EnumSource(value = PufType.class, names = {"INTEL", "EFUSE"})
    void getSetAuthorityFlowStrategy_Svn00_DeviceIdSkiNull_ForceEnrollmentFalse_Throws(PufType pufType) {
        // given
        try (var keyIdentifierUtilsMockedStatic = mockStatic(KeyIdentifierUtils.class)) {
            when(X509CertificateParser.toX509Certificate(ipcsEnrollmentCertBytes)).thenReturn(ipcsEnrollmentCert);
            when(KeyIdentifierUtils.getSubjectKeyIdentifier(deviceIdCert)).thenReturn(null);
            when(KeyIdentifierUtils.getSubjectKeyIdentifier(enrollmentDeviceIdCert)).thenReturn(new byte[]{1, 2, 3});

            // when - then
            assertThrows(SetAuthorityGenericException.class, () -> SetAuthorityFlow.getSetAuthorityFlowStrategy(pufType,
                Optional.of(deviceIdCertBytes), enrollmentDeviceIdCert, Optional.of(ipcsEnrollmentCertBytes), "00",
                false, akiVerifier, certificatesFromZipPathsHolder));
        }
    }

    @SneakyThrows
    @ParameterizedTest
    @EnumSource(value = PufType.class, names = {"INTEL", "EFUSE"})
    void getSetAuthorityFlowStrategy_Svn00_EnrollmentDeviceIdSkiNull_ForceEnrollmentFalse_Throws(PufType pufType) {
        // given
        try (var keyIdentifierUtilsMockedStatic = mockStatic(KeyIdentifierUtils.class)) {
            when(X509CertificateParser.toX509Certificate(ipcsEnrollmentCertBytes)).thenReturn(ipcsEnrollmentCert);
            when(KeyIdentifierUtils.getSubjectKeyIdentifier(deviceIdCert)).thenReturn(new byte[]{1, 2, 3});
            when(KeyIdentifierUtils.getSubjectKeyIdentifier(enrollmentDeviceIdCert)).thenReturn(null);

            // when - then
            assertThrows(SetAuthorityGenericException.class, () -> SetAuthorityFlow.getSetAuthorityFlowStrategy(pufType,
                Optional.of(deviceIdCertBytes), enrollmentDeviceIdCert, Optional.of(ipcsEnrollmentCertBytes), "00",
                false, akiVerifier, certificatesFromZipPathsHolder));
        }
    }
}
