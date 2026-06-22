/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2025 Altera Corporation. All Rights Reserved.
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

package com.intel.bkp.crypto.x509.validation;

import com.intel.bkp.crypto.x509.utils.X509CertificateUtils;
import com.intel.bkp.test.FileUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorityKeyIdentifierVerifierTest {

    // https://tsci.altera.com/content/IPCS/certs/attestation_B96D93594B94FD12_00000002.cer
    private static final String ATTESTATION_CERT_FILENAME = "attestation_B96D93594B94FD12_00000002.cer";
    // https://tsci.altera.com/content/IPCS/certs/IPCS_stratix10.cer
    private static final String PARENT_CERT_FILENAME = "IPCS_stratix10.cer";
    // https://tsci.altera.com/content/DICE/certs/DICE_RootCA.cer
    private static final String ROOT_CERT_FILENAME = "DICE_RootCA.cer";

    private static X509Certificate attestationCert;
    private static X509Certificate parentCert;
    private static X509Certificate rootCert;

    @Mock
    private X509Certificate certificate;

    private final AuthorityKeyIdentifierVerifier sut = new AuthorityKeyIdentifierVerifier();

    @BeforeAll
    static void init() {
        attestationCert = FileUtils.loadCertificate(ATTESTATION_CERT_FILENAME);
        parentCert = FileUtils.loadCertificate(PARENT_CERT_FILENAME);
        rootCert = FileUtils.loadCertificate(ROOT_CERT_FILENAME);
    }

    @Test
    void verify_ChildAKIMatchesParentSKI_ReturnsTrue() {
        // when-then
        assertTrue(sut.verify(attestationCert, parentCert));
    }

    @Test
    void verify_ChildHasNoAKI_isSelfSigned_ReturnsTrue() {
        // given
        when(certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId())).thenReturn(null);
        try (var x509CertUtilsStaticMock = mockStatic(X509CertificateUtils.class)) {
            when(X509CertificateUtils.isSelfSigned(certificate)).thenReturn(true);

            // when-then
            assertTrue(sut.verify(certificate, parentCert));
        }
    }

    @Test
    void verify_ChildHasNoAKI_isNotSelfSigned_ReturnsFalse() {
        // given
        when(certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId())).thenReturn(null);
        try (var x509CertUtilsStaticMock = mockStatic(X509CertificateUtils.class)) {
            when(X509CertificateUtils.isSelfSigned(certificate)).thenReturn(false);

            // when-then
            assertFalse(sut.verify(certificate, parentCert));
        }
    }

    @Test
    void verify_ParentHasNoSKI_ReturnsFalse() {
        // given
        when(certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId())).thenReturn(null);

        // when-then
        assertFalse(sut.verify(attestationCert, certificate));
    }

    @Test
    void verify_ChildAKIDoesNotMatchParentSKI_ReturnsFalse() {
        // when-then
        assertFalse(sut.verify(attestationCert, rootCert));
    }
}
