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

import com.intel.bkp.bkps.domain.enumeration.FamilyExtended;
import com.intel.bkp.bkps.exception.PrefetchingGenericException;
import com.intel.bkp.bkps.rest.onboarding.handler.PrefetchQueueProvider;
import com.intel.bkp.bkps.rest.onboarding.model.DeviceId;
import com.intel.bkp.crypto.x509.parsing.X509CertificateParser;
import com.intel.bkp.fpgacerts.model.Family;
import lombok.SneakyThrows;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;

import static com.intel.bkp.bkps.domain.enumeration.FamilyExtended.FAMILIES_WITH_PREFETCH_SUPPORTED;
import static com.intel.bkp.bkps.domain.enumeration.PrefetchType.ZIP_WITH_SKI;
import static com.intel.bkp.test.ParametrizedTestUtils.getAsArguments;
import static com.intel.bkp.test.RandomUtils.generateDeviceId;
import static com.intel.bkp.test.RandomUtils.getRandomOf;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.EnumSource.Mode.INCLUDE;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PrefetchServiceTest {

    private static final String UID = toHex(generateDeviceId()).toLowerCase(Locale.ROOT);
    private static final String ID = "SKI/AKI";
    private static final String PDI = "PDI";
    private static final byte[] CERT_BYTES = new byte[]{1, 2, 3, 4, 5};

    @Mock
    private X509Certificate x509Cert;

    @Mock
    private DeviceIdEnrollmentCertificate deviceIdEnrollmentCert;

    @Mock
    private PrefetchQueueProvider prefetchQueueProvider;

    @InjectMocks
    private PrefetchService sut;

    private static Stream<Arguments> getFamiliesThatDoNotUseSki() {
        return getAsArguments(getAllMatchingFamilies(
            f -> ZIP_WITH_SKI != f.getPrefetchType()
        ));
    }

    private static Stream<Arguments> getFamiliesThatRequireSki() {
        return getAsArguments(getListOfFamiliesThatRequireSki());
    }

    private static List<Family> getListOfFamiliesThatRequireSki() {
        return getAllMatchingFamilies(
            f -> ZIP_WITH_SKI == f.getPrefetchType()
        );
    }

    private static List<Family> getAllMatchingFamilies(Predicate<FamilyExtended> predicate) {
        return FamilyExtended.getAllMatching(predicate);
    }

    private static Stream<Arguments> getEmptyCerts() {
        return getAsArguments(
            Optional.empty(),
            Optional.of(new byte[0]),
            Optional.empty()
        );
    }

    @ParameterizedTest
    @MethodSource("getFamiliesThatDoNotUseSki")
    void enqueue_WithFamilyThatDoesNotRequireCert_WithNoCert_PushedToQueue(Family family) {
        // given
        final var deviceId = spy(DeviceId.instance(family, UID, PDI));

        // when-then
        sut.enqueue(deviceId, Optional.empty());

        // then
        verify(deviceId, never()).setExplicitId(any());
        verifyPushToQueue(deviceId);
    }

    @ParameterizedTest
    @MethodSource("getFamiliesThatRequireSki")
    @SneakyThrows
    void enqueue_WithFamilyThatRequiresCert_WithCert_PushedToQueue(Family family) {
        // given
        final var deviceId = spy(DeviceId.instance(family, UID));

        try (var deviceIdErCertMockedStatic = mockStatic(DeviceIdEnrollmentCertificate.class);
             var x509ParserMockedStatic = mockStatic(X509CertificateParser.class)) {
            when(X509CertificateParser.toX509Certificate(CERT_BYTES)).thenReturn(x509Cert);
            when(DeviceIdEnrollmentCertificate.from(x509Cert)).thenReturn(deviceIdEnrollmentCert);
            when(deviceIdEnrollmentCert.getKeyIdentifierBasedOnSvn()).thenReturn(ID);

            // when
            sut.enqueue(deviceId, Optional.of(CERT_BYTES));
        }

        // then
        verify(deviceId).setExplicitId(ID);
        verifyPushToQueue(deviceId);
    }

    @ParameterizedTest
    @MethodSource("getFamiliesThatRequireSki")
    void enqueue_WithFamilyThatRequiresCert_WithInvalidCert_Throws(Family family) {
        // given
        final var deviceId = DeviceId.instance(family, UID);
        final var invalidCert = new byte[]{1, 2, 3};

        // when-then
        final var exception = assertThrows(PrefetchingGenericException.class,
            () -> sut.enqueue(deviceId, Optional.of(invalidCert)));

        // then
        verifyNothingQueued();
        assertEquals("Parsing certificate failed.", exception.getMessage());
    }

    @ParameterizedTest
    @MethodSource("getEmptyCerts")
    void enqueue_WithFamilyThatRequiresCert_WithNoCert_Throws(Optional<byte[]> emptyCert) {
        // given
        final var family = getRandomOf(getListOfFamiliesThatRequireSki());
        final var deviceId = DeviceId.instance(family, UID);

        // when-then
        final var exception = assertThrows(PrefetchingGenericException.class,
            () -> sut.enqueue(deviceId, emptyCert));

        // then
        verifyNothingQueued();
    }

    @ParameterizedTest
    @EnumSource(value = Family.class, mode = INCLUDE, names = {"MEV", "LKV", "CNV"})
    void enqueue_WithFamilyThatDoesNotSupportPrefetch_Throws(Family family) {
        // given
        final var deviceId = DeviceId.instance(family, UID);

        // when-then
        final var exception = assertThrows(PrefetchingGenericException.class,
            () -> sut.enqueue(deviceId, Optional.empty()));

        // then
        verifyNothingQueued();
        assertEquals("Prefetching is only supported for platforms: " + FAMILIES_WITH_PREFETCH_SUPPORTED,
            exception.getMessage());
    }

    private void verifyPushToQueue(DeviceId deviceId) {
        verify(prefetchQueueProvider).pushToQueue(deviceId);
    }

    private void verifyNothingQueued() {
        verify(prefetchQueueProvider, never()).pushToQueue(any());
    }
}
