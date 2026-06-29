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

package com.intel.bkp.bkps.security;

import com.intel.bkp.bkps.exception.X509TrustManagerException;
import com.intel.bkp.core.helper.TruststoreCertificateEntryData;
import com.intel.bkp.crypto.CryptoUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.PrincipalUtil;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class X509TrustManagerManager {

    private final KeyStoreWrapper keyStoreWrapper;

    public List<TruststoreCertificateEntryData> getCertificateInfoList()
        throws KeyStoreException {
        reloadTrustManager();
        ArrayList<TruststoreCertificateEntryData> list = new ArrayList<>();
        Enumeration<String> aliases = this.keyStoreWrapper.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            TruststoreCertificateEntryData data = Optional
                .ofNullable(this.keyStoreWrapper.getCertificate(alias))
                .filter(cert -> "X.509".equals(cert.getType()))
                .map(cert -> {
                    X509Certificate certificate = (X509Certificate) cert;
                    try {
                        final TruststoreCertificateEntryData entry =
                            new TruststoreCertificateEntryData(alias, cert.getEncoded());
                        entry.setValidUntil(certificate.getNotAfter().toInstant());
                        entry.setSubject(PrincipalUtil.getSubjectX509Principal(certificate).getName());
                        return entry;
                    } catch (CertificateEncodingException e) {
                        log.error("Failed to get encoded x509 certificate", e);
                        return null;
                    }
                })
                .orElseGet(() -> new TruststoreCertificateEntryData(alias));

            list.add(data);
        }
        return list;
    }

    public void addEntry(X509Certificate certificate, String newAlias) throws X509TrustManagerException {
        try {
            if (fingerprintExists(CryptoUtils.generateFingerprint(certificate.getEncoded()))) {
                throw new X509TrustManagerException("Given certificate fingerprint already exists in trust store");
            }

            this.keyStoreWrapper.setCertificateEntry(newAlias, certificate);
            this.keyStoreWrapper.store();
            reloadTrustManager();
        } catch (KeyStoreException | NoSuchAlgorithmException | IOException | CertificateException e) {
            throw new X509TrustManagerException("Failed to store certificate in trust store", e);
        }
    }

    public boolean exists(String alias) throws X509TrustManagerException {
        try {
            reloadTrustManager();
            return this.keyStoreWrapper.containsAlias(alias);
        } catch (KeyStoreException e) {
            throw new X509TrustManagerException("Failed to check if alias exists in trust store", e);
        }
    }

    public void removeEntry(String alias) throws X509TrustManagerException {
        try {
            reloadTrustManager();
            this.keyStoreWrapper.deleteEntry(alias);
            this.keyStoreWrapper.store();
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException
                 | IOException e) {
            throw new X509TrustManagerException("Failed to remove certificate from trust store", e);
        }
    }

    public boolean fingerprintExists(final String fingerprint)
        throws X509TrustManagerException, KeyStoreException, NoSuchAlgorithmException {
        List<TruststoreCertificateEntryData> certificateInfoList = getCertificateInfoList();
        return certificateInfoList.stream().anyMatch(entry -> fingerprint.equals(entry.getFingerprint()));
    }

    private void reloadTrustManager() {
        log.debug("Opening trust store file....");
        try {
            keyStoreWrapper.load();
        } catch (NoSuchAlgorithmException | IOException | KeyStoreException e) {
            log.error("Failed to load trust store", e);
        } catch (CertificateException e) {
            log.error("Failed to load certificate from trust store", e);
        }
    }
}
