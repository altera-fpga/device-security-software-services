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

package com.intel.bkp.bkps.rest.onboarding.service;

import com.intel.bkp.fpgacerts.dice.subject.DiceCertificateSubject;
import com.intel.bkp.utils.Base64Url;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static com.intel.bkp.test.FileUtils.loadCertificate;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

class DeviceIdEnrollmentCertificateTest {

    private static final String DEVICE_ID_ENROLLMENT_CERT = "device_id_enrollment_certificate.der";
    private static final String AKI =
        Base64Url.encodeWithoutPadding(fromHex("57DED154342188052F18671AE0950BBBD71E533A"));
    private static final String SKI =
        Base64Url.encodeWithoutPadding(fromHex("0C8F77D5B466BA2C662F25B858963249E4220DA4"));

    private static X509Certificate realCert;
    private static DiceCertificateSubject realIssuer;

    private static Stream<Arguments> getAllSvnValues() {
        return IntStream.range(0, 32).mapToObj(Arguments::of);
    }

    @SneakyThrows
    @BeforeAll
    static void init() {
        realCert = loadCertificate(DEVICE_ID_ENROLLMENT_CERT);
        realIssuer = DiceCertificateSubject.parse(realCert.getIssuerX500Principal().toString());
    }

    @ParameterizedTest
    @MethodSource("getAllSvnValues")
    void getSvn_Success(int expectedSvn) {
        // given
        final DeviceIdEnrollmentCertificate sut = prepareSut(expectedSvn);

        // when
        final int svn = sut.getSvn();

        // then
        assertEquals(expectedSvn, svn);
    }

    @ParameterizedTest
    @MethodSource("getAllSvnValues")
    void getKeyIdentifierBasedOnSvn_Success(int svn) {
        // given
        final var expectedKi = svn == 0 ? SKI : AKI;
        final DeviceIdEnrollmentCertificate sut = prepareSut(svn);

        // when
        final String ki = sut.getKeyIdentifierBasedOnSvn();

        // then
        assertEquals(expectedKi, ki);
    }

    private DeviceIdEnrollmentCertificate prepareSut(int svn) {
        return DeviceIdEnrollmentCertificate.from(getCertWithSvn(svn));
    }

    private X509Certificate getCertWithSvn(int expectedSvn) {
        final var certSpy = spy(realCert);
        when(certSpy.getIssuerX500Principal()).thenReturn(getIssuerWithSvn(expectedSvn));
        return certSpy;
    }

    private X500Principal getIssuerWithSvn(int svn) {
        final String mockedSvn = toHex(svn).toLowerCase(Locale.ROOT);
        return new X500Principal(DiceCertificateSubject.build(
            realIssuer.familyName(), realIssuer.level(), mockedSvn, realIssuer.deviceId()
        ));
    }


}
