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

package com.intel.bkp.crypto.x509.validation;

import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.crypto.x509.utils.KeyIdentifierUtils.calculateSubjectKeyIdentifierUsingMethod2FromRfc7093;
import static com.intel.bkp.crypto.x509.utils.KeyIdentifierUtils.getSubjectKeyIdentifier;
import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
public class SubjectKeyIdentifierVerifier {

    private List<X509Certificate> certificates = new LinkedList<>();

    public SubjectKeyIdentifierVerifier certificates(List<X509Certificate> certificates) {
        this.certificates = certificates;
        return this;
    }

    public boolean verify() {
        return certificates.stream().allMatch(this::verifyCertificate);
    }

    private boolean verifyCertificate(final X509Certificate certificate) {
        return Optional.ofNullable(getSubjectKeyIdentifier(certificate))
            .map(skiFromCert -> validateSki(certificate, skiFromCert))
            .orElseGet(() -> handleNoSki(certificate));
    }

    private static boolean handleNoSki(X509Certificate certificate) {
        log.debug("Certificate does not contain SKI extension: {}", certificate.getSubjectX500Principal());
        return true;
    }

    private static boolean validateSki(X509Certificate certificate, byte[] skiFromCert) {
        final byte[] calculatedSki = calculateSubjectKeyIdentifierUsingMethod2FromRfc7093(certificate.getPublicKey());
        final boolean valid = Arrays.equals(calculatedSki, skiFromCert);
        if (!valid) {
            log.error("""
                    Certificate has incorrect SKI value: {}
                    Expected (calculated with method 2 from RFC7093): {}
                    Actual: {}""", certificate.getSubjectX500Principal(), toHex(calculatedSki),
                toHex(skiFromCert));
        }
        return valid;
    }
}
