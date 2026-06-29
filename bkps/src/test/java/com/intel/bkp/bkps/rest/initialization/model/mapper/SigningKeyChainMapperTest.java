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

package com.intel.bkp.bkps.rest.initialization.model.mapper;

import com.intel.bkp.bkps.domain.SigningKeyCertificate;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.test.CertificateUtils;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SigningKeyChainMapperTest {

    private final SigningKeyChainMapper sut = Mappers.getMapper(SigningKeyChainMapper.class);

    @Test
    void signingKeyChainToFingerprintList_WithNullChain_ReturnsNull() {
        // when
        final List<String> result = sut.signingKeyChainToFingerprintList(null);

        // then
        assertNull(result);
    }

    @Test
    void signingKeyChainToFingerprintList_WithEmptyChain_ReturnsEmptyList() {
        // given
        final List<SigningKeyCertificate> emptyChain = List.of();

        // when
        final List<String> result = sut.signingKeyChainToFingerprintList(emptyChain);

        // then
        assertTrue(result.isEmpty());
    }

    @Test
    void signingKeyChainToFingerprintList_WithChain_ReturnsList() {
        // given
        final var first = generateSigningKeyCertWithFingerprint(1L);
        final var second = generateSigningKeyCertWithFingerprint(2L);

        final List<SigningKeyCertificate> chainInCorrectOrder = toCertList(first, second);
        final List<String> expected = toFingerprintList(first, second);

        // when
        final List<String> result = sut.signingKeyChainToFingerprintList(chainInCorrectOrder);

        // then
        assertIterableEquals(expected, result);
    }

    @Test
    void signingKeyChainToFingerprintList_WithChainInWrongOrder_ReturnsListInCorrectOrder() {
        // given
        final var first = generateSigningKeyCertWithFingerprint(1L);
        final var second = generateSigningKeyCertWithFingerprint(2L);
        final var third = generateSigningKeyCertWithFingerprint(3L);

        final List<SigningKeyCertificate> chainInWrongOrder = toCertList(third, first, second);
        final List<String> expected = toFingerprintList(first, second, third);

        // when
        final List<String> result = sut.signingKeyChainToFingerprintList(chainInWrongOrder);

        // then
        assertIterableEquals(expected, result);
    }

    @SneakyThrows
    private SigningKeyCertWithFingerprint generateSigningKeyCertWithFingerprint(Long id) {
        final byte[] x509CertBytes = CertificateUtils.generateCertificate().getEncoded();
        final var signingKeyCert = new SigningKeyCertificate();
        signingKeyCert.setCertificate(x509CertBytes);
        signingKeyCert.setId(id);

        final String fingerprint = CryptoUtils.generateFingerprint(x509CertBytes);

        return new SigningKeyCertWithFingerprint(signingKeyCert, fingerprint);
    }

    private List<SigningKeyCertificate> toCertList(SigningKeyCertWithFingerprint... certsWithFingerprints) {
        return Arrays.stream(certsWithFingerprints)
                .map(SigningKeyCertWithFingerprint::getCertificate)
                .collect(Collectors.toList());
    }

    private List<String> toFingerprintList(SigningKeyCertWithFingerprint... certsWithFingerprints) {
        return Arrays.stream(certsWithFingerprints)
                .map(SigningKeyCertWithFingerprint::getFingerprint)
                .collect(Collectors.toList());
    }

    @RequiredArgsConstructor
    @Getter
    static class SigningKeyCertWithFingerprint {
        private final SigningKeyCertificate certificate;
        private final String fingerprint;
    }
}
