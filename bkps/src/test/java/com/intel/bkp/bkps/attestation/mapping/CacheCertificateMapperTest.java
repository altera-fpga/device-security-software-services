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

package com.intel.bkp.bkps.attestation.mapping;

import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Optional;

import static com.intel.bkp.crypto.x509.utils.X509CertificateUtils.toPem;
import static com.intel.bkp.test.CertificateUtils.generateCertificate;
import static org.junit.jupiter.api.Assertions.assertEquals;

class CacheCertificateMapperTest {

    private static X509Certificate cert;

    private static String certInPem;

    private static byte[] certBytes;

    private final CacheCertificateMapper sut = new CacheCertificateMapper();

    @SneakyThrows
    @BeforeAll
    static void prepareCrl() {
        cert = generateCertificate();
        certInPem = toPem(cert);
        certBytes = cert.getEncoded();
    }

    @Test
    void encode_Success() {
        // when-then
        assertEquals(certInPem, sut.encode(cert));
    }

    @Test
    void decode_Success() {
        // when-then
        assertEquals(cert, sut.decode(certInPem));
    }

    @Test
    void parse_Success() {
        // when-then
        assertEquals(Optional.of(cert), sut.parse(certBytes));
    }
}
