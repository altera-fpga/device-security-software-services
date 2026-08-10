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

package com.intel.bkp.bkps.utils;

import com.intel.bkp.bkps.exception.CertificateChainValidationFailed;
import com.intel.bkp.bkps.exception.CertificateManagerException;
import com.intel.bkp.bkps.exception.CertificateWrongFormat;
import com.intel.bkp.bkps.exception.MissingLeafCertificate;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.exceptions.X509CertificateParsingException;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.toX509Certificate;
import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.toX509CertificateChain;

@Getter
@Slf4j
public class CertificateManager {

    private static final int EXPECTED_SIGNING_KEY_CERT_CHAIN_LENGTH = 2;

    @Setter
    private List<X509Certificate> certificates = new ArrayList<>();

    public static byte[] getCertificateContent(X509Certificate certificate) {
        try {
            return certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new CertificateChainValidationFailed();
        }
    }

    public static String getCertificateFingerprint(String certificate) throws X509CertificateParsingException {
        return CryptoUtils.generateFingerprint(
            getCertificateContent(parseContent(certificate.getBytes(StandardCharsets.UTF_8)))
        );
    }

    public static String getCertificateFingerprint(X509Certificate certificate) {
        return CryptoUtils.generateFingerprint(getCertificateContent(certificate));
    }

    public static X509Certificate parseContent(byte[] certificateContent) throws X509CertificateParsingException {
        return Optional.ofNullable(toX509Certificate(certificateContent)).orElseThrow(
            () -> new BKPBadRequestException(ErrorCodeMap.FAILED_TO_PARSE_CERTIFICATE)
        );
    }

    public void parseChain(byte[] certificateChainBytes) {
        try {
            this.certificates = toX509CertificateChain(certificateChainBytes);
        } catch (X509CertificateParsingException e) {
            throw new CertificateWrongFormat(e);
        }
    }

    public void verifyChainListSize() {
        if (this.certificates.size() < EXPECTED_SIGNING_KEY_CERT_CHAIN_LENGTH) {
            throw new CertificateManagerException(ErrorCodeMap.CERTIFICATE_CHAIN_WRONG_SIZE);
        }
    }

    private boolean verifyParentsInChainByPubKeyRecursive(X509Certificate child,
                                                          Iterator<X509Certificate> certificateChainIterator) {
        if (certificateChainIterator.hasNext()) {
            try {
                X509Certificate parent = certificateChainIterator.next();
                child.verify(parent.getPublicKey());

                return verifyParentsInChainByPubKeyRecursive(parent, certificateChainIterator);
            } catch (CertificateException | NoSuchAlgorithmException
                | InvalidKeyException | NoSuchProviderException | SignatureException e) {
                return false;
            }
        }

        return true;
    }

    public void verifyParentsInChainByPubKey() {
        Iterator<X509Certificate> certificateChainIterator = this.certificates.iterator();
        if (certificateChainIterator.hasNext()
            && !verifyParentsInChainByPubKeyRecursive(certificateChainIterator.next(), certificateChainIterator)) {
            throw new CertificateManagerException(ErrorCodeMap.PARENT_CERTIFICATES_DO_NOT_MATCH);
        }
    }

    public X509Certificate getLeafCertificate() {
        if (!this.certificates.isEmpty()) {
            return this.certificates.get(0);
        }
        throw new MissingLeafCertificate();
    }
}
