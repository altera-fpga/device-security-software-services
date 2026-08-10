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

package com.intel.bkp.crypto.pem;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.x509.parsing.X509CertificateParser;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.intel.bkp.crypto.constants.CryptoConstants.EC_KEY;
import static com.intel.bkp.crypto.pem.PemFormatHeader.CRL;
import static com.intel.bkp.crypto.pem.PemFormatHeader.CSR;
import static com.intel.bkp.crypto.pem.PemFormatHeader.PUBLIC_KEY;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PemFormatEncoderTest {

    private static final byte[] EXPECTED_BYTES = new byte[]{0, 1, 2, 3, 4};

    private static final String PUBLIC_KEY_PEM =
        """
            -----BEGIN PUBLIC KEY-----
            MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEnfZwXOcDJkzAIneeSWLE4fw0ItHswu1K
            ytIRBJxTr6HoZQEgRx+QCDlrlphcAengLery3XKP0iGt/W6Pe1kcPKEJmkQvZul8
            Qpxba17YIpAuSyNGyTythnjAs7i1SHSa
            -----END PUBLIC KEY-----""";
    private static final String PEM_INVALID_HEADER = "-----BEGIN INVALID PEM-----";
    private static final String PEM_EMPTY = "";
    private static final String PUBLIC_KEY_PEM_INVALID_CONTENT =
        """
            -----BEGIN PUBLIC KEY-----
            ytIRBJxTr6HoZQEgRx
            -----END PUBLIC KEY-----""";

    private static final String CERTIFICATE_PEM = """
        -----BEGIN CERTIFICATE-----
        MIIEMjCCA7igAwIBAgIUIwAAAPwgqlcL1AF5SNek1kvv1CIwCgYIKoZIzj0EAwMw
        LjEsMCoGA1UEAwwjSW50ZWw6QWdpbGV4OkVSOjAwOjIyZDRlZjRiZDZhNGQ3NDgw
        IBcNNzAwMTAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMDwxOjA4BgNVBAMMMUlu
        dGVsOkFnaWxleDpMMDo1RjdXMkFqRThYMHI2M0dXOjIyZDRlZjRiZDZhNGQ3NDgw
        djAQBgcqhkjOPQIBBgUrgQQAIgNiAATJzSe8jKcrT3JQ4KuXa5LnWJoCCTCkxQGV
        3uqYifa2IW12T5jByREAff4nP4FXHNcvYfCbGZz72NXy2CwxYya6LKniwBW7oWgA
        +EgR2/RPTZb12Nhrv5ot9BUHXalEpR2jggKFMIICgTAOBgNVHQ8BAf8EBAMCAgQw
        HgYDVR0lAQH/BBQwEgYHZ4EFBQRkBgYHZ4EFBQRkDDAeBgorBgEEAYMcghIGBBAw
        DjAMBgorBgEEAYMcghICMBIGA1UdEwEB/wQIMAYBAf8CAQEwSQYDVR0fBEIwQDA+
        oDygOoY4aHR0cHM6Ly90c2NpLmludGVsLmNvbS9jb250ZW50L0lQQ1MvY3Jscy9J
        UENTX2FnaWxleC5jcmwwHQYDVR0OBBYEFORe1tgIxPF9K+txlshavMgqwQCWMB8G
        A1UdIwQYMBaAFOKp91yAWltHvKbynGRhvs8IcsUZMIIBbgYGZ4EFBQQFAQH/BIIB
        XzCCAVswXYAJaW50ZWwuY29tgQZBZ2lsZXiDAQCEAQCFAQCmPzA9BglghkgBZQME
        AgIEMDAuabpuP6w0CldWEjToi/6y/jc7zk1KKMJEgJy0Z8Mco5h0zQ0/NG/KKpro
        dKHWazA9gAlpbnRlbC5jb22EAQCIII/HkIgPMBkKDwAA8I8FVQUAcNk/AACXRwAA
        l0c8bQZXiQtghkgBhvhNAQ8EBzBdgAlpbnRlbC5jb22EAQCIQFDoAH1I16TWS+/U
        Il87/TQfACl4xyQq3imufjqxbXjHPLzV1nkcdFIii5dygrAxB5loWW9IIPNAJGp2
        rdGtiVWJC2CGSAGG+E0BDwQIMFyACWludGVsLmNvbYQBAKY/MD0GCWCGSAFlAwQC
        AgQwBl/li6+1MuG8afqTz4egCjkHke6Wq9wzlPCjXzWqETcV1MdPaGs5MAAGIrqY
        AQXYiQtghkgBhvhNAQ8ECTAeBgZngQUFBAQEFDASBBACAAftAAA0AEjXpNZL79Qi
        MAoGCCqGSM49BAMDA2gAMGUCMQC4EsZ8ZangTH33ZBbjsETr2UPdV37NGAClaVOD
        qU0jNsYxRTX4cW/ZtF/k5WE9PhQCMBTmscfa+hj5alMGLcUhU8jwV14RzKirBHT7
        3Gfjq7aPDLnq68Tr1XgtUfYYDlymkA==
        -----END CERTIFICATE-----""";

    @Test
    void encodeCertificateRequest_ShouldEncodeCertificateRequest() {
        // given
        byte[] content = "test".getBytes();
        String output = String.format("%s%s%s", CSR.getBegin(), "dGVzdA==", CSR.getEnd());

        // when
        String encoded = PemFormatEncoder.encode(CSR, content);

        // then
        assertEquals(output, encoded.replaceAll("\r", "").replaceAll("\n", ""));
    }

    @Test
    void encodeCrlRequest_ShouldEncodeCrlRequest() {
        // given
        byte[] content = "test".getBytes();
        String output = String.format("%s%s%s", CRL.getBegin(), "dGVzdA==", CRL.getEnd());

        // when
        String encoded = PemFormatEncoder.encode(CRL, content);

        // then
        assertEquals(output, encoded.replaceAll("\r", "").replaceAll("\n", ""));
    }


    @Test
    void encodePublicKey_SuccessfullyEncodesData() {
        // when
        String result = PemFormatEncoder.encode(PUBLIC_KEY, EXPECTED_BYTES);

        // then
        assertNotNull(result);
        assertTrue(result.contains(PUBLIC_KEY.getBegin()));
        assertTrue(result.contains(PUBLIC_KEY.getEnd()));
    }

    @Test
    void decode_ValidPem_SuccessfullyRecoversKey() throws IOException {
        // when
        final byte[] result = PemFormatEncoder.decode(PUBLIC_KEY_PEM.getBytes(StandardCharsets.UTF_8));

        // then
        assertDoesNotThrow(() -> CryptoUtils.toPublicEncodedBC(result, EC_KEY));
    }

    @Test
    void decode_InvalidPemHeader_ThrowsIllegalArgumentException() {
        // when-then
        assertThrows(IllegalArgumentException.class,
            () -> PemFormatEncoder.decode(PEM_INVALID_HEADER.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void decode_EmptyPemContent_ThrowsIllegalArgumentException() {
        // when-then
        assertThrows(IllegalArgumentException.class,
            () -> PemFormatEncoder.decode(PEM_EMPTY.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void decode_InvalidPemContent_ThrowsIllegalArgumentException() {
        // when-then
        assertThrows(IllegalArgumentException.class,
            () -> PemFormatEncoder.decode(PUBLIC_KEY_PEM_INVALID_CONTENT.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void decode_ValidCertificatePem_SuccessfullyRecoversCertificate() throws IOException {
        // when
        final byte[] result = PemFormatEncoder.decode(CERTIFICATE_PEM);

        // then
        assertDoesNotThrow(() -> X509CertificateParser.toX509Certificate(result));
    }

    @Test
    void decode_InvalidCertPemHeader_ThrowsIllegalArgumentException() {
        // when-then
        assertThrows(IllegalArgumentException.class,
            () -> PemFormatEncoder.decode(PEM_INVALID_HEADER));
    }

    @Test
    void decode_EmptyCertPemContent_ThrowsIllegalArgumentException() {
        // when-then
        assertThrows(IllegalArgumentException.class,
            () -> PemFormatEncoder.decode(PEM_EMPTY));
    }
}
