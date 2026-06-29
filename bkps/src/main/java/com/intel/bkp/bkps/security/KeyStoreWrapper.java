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

import com.intel.bkp.bkps.config.TrustStoreProperties;
import com.intel.bkp.core.interfaces.ICustomKeyStore;
import org.springframework.stereotype.Service;

import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;

@Service
public class KeyStoreWrapper implements ICustomKeyStore {

    private final KeyStore keyStore;

    private final TrustStoreProperties trustStoreProperties;

    protected KeyStoreWrapper(TrustStoreProperties trustStoreProperties) throws KeyStoreException {
        this.trustStoreProperties = trustStoreProperties;
        this.keyStore = KeyStore.getInstance(this.trustStoreProperties.getType());
    }

    @Override
    public Enumeration<String> aliases() throws KeyStoreException {
        return this.keyStore.aliases();
    }

    @Override
    public Certificate getCertificate(String alias) throws KeyStoreException {
        return this.keyStore.getCertificate(alias);
    }

    @Override
    public void setCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        this.keyStore.setCertificateEntry(alias, cert);
    }

    @Override
    public void store() throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        try (OutputStream outputStream = this.trustStoreProperties.getLocation().getOutputStream()) {
            this.keyStore.store(outputStream, this.trustStoreProperties.getPassword().toCharArray());
        }
    }

    @Override
    public boolean containsAlias(String alias) throws KeyStoreException {
        return this.keyStore.containsAlias(alias);
    }

    @Override
    public void deleteEntry(String alias) throws KeyStoreException {
        this.keyStore.deleteEntry(alias);
    }

    @Override
    public void load() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        try (InputStream inputStream = this.trustStoreProperties.getLocation().getInputStream()) {
            this.load(inputStream);
        }
    }

    void load(InputStream inputStream) throws IOException, CertificateException, NoSuchAlgorithmException,
        KeyStoreException {
        this.keyStore.load(inputStream, this.trustStoreProperties.getPassword().toCharArray());
        final var tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(this.keyStore);
    }

    void setKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        this.keyStore.setKeyEntry(alias, key, password, chain);
    }
}
