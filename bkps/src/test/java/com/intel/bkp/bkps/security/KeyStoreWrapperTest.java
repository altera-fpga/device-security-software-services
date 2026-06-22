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

package com.intel.bkp.bkps.security;

import com.intel.bkp.bkps.config.TrustStoreProperties;
import com.intel.bkp.test.CertificateUtils;
import com.intel.bkp.test.KeyGenUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.FileSystemResource;

import java.io.File;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KeyStoreWrapperTest {

    private static final String KEYSTORE_PASSWORD = "test";
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String KEYSTORE_LOCATION = "tmpTruststore.jks";

    private static final String KEY_ENTRY_NAME = "myKey";
    private static final String CERT_ENTRY_NAME = "myCert";
    @TempDir
    File tempDir;
    @Mock
    private TrustStoreProperties trustStoreProperties;
    private KeyStoreWrapper sut;
    private X509Certificate certificate;

    private File keystoreFile;

    @BeforeEach
    void setUp() throws Exception {
        this.certificate = CertificateUtils.generateCertificate();

        Path keystorePath = tempDir.toPath().resolve(KEYSTORE_LOCATION);
        this.keystoreFile = keystorePath.toFile();

        mockTrustStoreProperties();
        sut = new KeyStoreWrapper(trustStoreProperties);

        initCustomTruststore();
    }

    @Test
    void aliases_Success() throws KeyStoreException {
        // given
        List<String> givenAliases = new ArrayList<>();
        givenAliases.add(CERT_ENTRY_NAME.toLowerCase());
        givenAliases.add(KEY_ENTRY_NAME.toLowerCase());

        // when
        final var aliases = sut.aliases();

        // then
        final var actual = Collections.list(aliases).stream().toList();
        assertTrue(actual.size()==givenAliases.size() && actual.containsAll(givenAliases)
            && givenAliases.containsAll(actual));
    }

    @Test
    void getCertificate_Success() throws KeyStoreException {
        // when
        final var actual = sut.getCertificate("mycert");

        // then
        assertEquals(certificate, actual);
    }

    @Test
    void store_Success() {
        // given
        when(trustStoreProperties.getLocation()).thenReturn(new FileSystemResource(keystoreFile));
        when(trustStoreProperties.getPassword()).thenReturn(KEYSTORE_PASSWORD);

        // when - then
        assertDoesNotThrow(() -> sut.store());
    }

    @Test
    void load_Success() {
        // given
        when(trustStoreProperties.getLocation()).thenReturn(new FileSystemResource(keystoreFile));
        when(trustStoreProperties.getPassword()).thenReturn(KEYSTORE_PASSWORD);

        // when - then
        assertDoesNotThrow(() -> sut.load());
    }

    private void initCustomTruststore() throws Exception {
        sut.load(null);

        // Add the certificate
        sut.setCertificateEntry(CERT_ENTRY_NAME, certificate);
        sut.setKeyEntry(KEY_ENTRY_NAME, KeyGenUtils.genRsa1024().getPrivate(), KEYSTORE_PASSWORD.toCharArray(),
            new Certificate[]{CertificateUtils.generateCertificate()});

        // Save the new keystore contents
        sut.store();
    }

    private void mockTrustStoreProperties() {
        when(trustStoreProperties.getType()).thenReturn(KEYSTORE_TYPE);
        when(trustStoreProperties.getLocation()).thenReturn(new FileSystemResource(keystoreFile));
        when(trustStoreProperties.getPassword()).thenReturn(KEYSTORE_PASSWORD);
    }
}


