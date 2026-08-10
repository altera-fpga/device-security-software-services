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

package com.intel.bkp.fpgacerts.utils;

import com.intel.bkp.crypto.x509.utils.AuthorityInformationAccessUtils;
import com.intel.bkp.fpgacerts.exceptions.X509Exception;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.Optional;

import static com.intel.bkp.test.FileUtils.readFromResources;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mockStatic;

@ExtendWith(MockitoExtension.class)
class X509UtilsWrapperTest {

    private static final String TEST_FOLDER = "certs/s10/";

    // https://tsci.altera.com/content/IPCS/certs/IPCS_stratix10.cer
    private static final String PARENT_CERT_FILENAME = "IPCS_stratix10.cer";
    private static final String CERT_SUBJECT = "CN=Intel:Stratix10:IPCS";
    private static final String ISSUER_URL = "https://tsci.altera.com/content/DICE/certs/DICE_RootCA.cer";

    private static byte[] certificate;

    @BeforeAll
    static void init() throws Exception {
        certificate = readFromResources(TEST_FOLDER, PARENT_CERT_FILENAME);
    }

    @Test
    void toX509_Success() {
        // when
        X509Certificate result = X509UtilsWrapper.toX509(certificate);

        // then
        assertEquals(CERT_SUBJECT, result.getSubjectX500Principal().toString());
    }

    @Test
    void toX509_ParsingFailed_Throws() {
        // when-then
        assertThrows(X509Exception.class, () -> X509UtilsWrapper.toX509(new byte[]{1, 2}));
    }

    @Test
    void getIssuerCertUrl_Success() {
        // given
        final X509Certificate cert = X509UtilsWrapper.toX509(certificate);

        // when
        final String result = X509UtilsWrapper.getIssuerCertUrl(cert);

        // then
        assertEquals(ISSUER_URL, result);
    }

    @Test
    void getIssuerCertUrl_Throws() {
        // given
        final X509Certificate cert = X509UtilsWrapper.toX509(certificate);

        // when-then
        try (var utils = mockStatic(AuthorityInformationAccessUtils.class)) {
            utils.when(() -> AuthorityInformationAccessUtils.getIssuerCertUrl(cert)).thenReturn(Optional.empty());
            assertThrows(X509Exception.class, () -> X509UtilsWrapper.getIssuerCertUrl(cert));
        }
    }
}
