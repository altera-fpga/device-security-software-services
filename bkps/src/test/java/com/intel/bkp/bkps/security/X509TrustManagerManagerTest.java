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
import com.intel.bkp.bkps.exception.X509TrustManagerException;
import com.intel.bkp.core.helper.TruststoreCertificateEntryData;
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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class X509TrustManagerManagerTest {

    private static final String KEYSTORE_PASSWORD = "test";
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String KEYSTORE_LOCATION = "tmpTruststore.jks";

    private static final String KEY_ENTRY_NAME = "myKey";
    private static final String CERT_ENTRY_NAME = "myCert";

    @Mock
    private TrustStoreProperties trustStoreProperties;

    private KeyStoreWrapper keyStoreWrapper;

    private X509TrustManagerManager sut;

    @TempDir
    File tempDir;

    private X509Certificate certificate;

    @BeforeEach
    void setUp() throws Exception {
        this.certificate = CertificateUtils.generateCertificate();
        mockTrustStoreProperties();
        this.keyStoreWrapper = new KeyStoreWrapper(trustStoreProperties);

        initCustomTruststore();
        sut = new X509TrustManagerManager(keyStoreWrapper);
    }

    @Test
    void getCertificateInfoList_Success() throws Exception {
        // when
        List<TruststoreCertificateEntryData> result = sut.getCertificateInfoList();

        // then
        assertEquals(2, result.size());
        assertTrue(result.stream().anyMatch(entry -> entry.getAlias().equalsIgnoreCase(KEY_ENTRY_NAME)));
        assertTrue(result.stream().anyMatch(entry -> entry.getAlias().equalsIgnoreCase(CERT_ENTRY_NAME)));
    }

    @Test
    void exists_WithExistingAlias_ReturnsTrue() throws Exception {
        // when
        boolean result = sut.exists(KEY_ENTRY_NAME);

        // then
        assertTrue(result);
    }

    @Test
    void exists_WithNotExistingAlias_ReturnsFalse() throws Exception {
        // when
        boolean result = sut.exists("NOT_EXISTING_ALIAS");

        // then
        assertFalse(result);
    }

    @Test
    void removeEntry_Success() throws Exception {
        // given
        boolean resultBeforeRemove = sut.exists(KEY_ENTRY_NAME);

        // when
        sut.removeEntry(KEY_ENTRY_NAME);

        // then
        assertTrue(resultBeforeRemove);
        assertFalse(sut.exists(KEY_ENTRY_NAME));
    }

    @Test
    void addEntry_Success() throws Exception {
        // given
        final String newAlias = "NEW_TEST_ALIAS";
        boolean resultBeforeAdd = sut.exists(newAlias);

        // when
        sut.addEntry(CertificateUtils.generateCertificate(), newAlias);

        // then
        assertFalse(resultBeforeAdd);
        assertTrue(sut.exists(newAlias));
    }

    @Test
    void addEntry_WithExistingAlias_ThrowsException() {
        // when-then
        assertThrows(X509TrustManagerException.class,
            () -> sut.addEntry(this.certificate, "NEW_TEST_ALIAS"));
    }

    private void initCustomTruststore() throws Exception {
        this.keyStoreWrapper.load(null);

        // Add the certificate
        this.keyStoreWrapper.setCertificateEntry(CERT_ENTRY_NAME, certificate);
        this.keyStoreWrapper.setKeyEntry(KEY_ENTRY_NAME, KeyGenUtils.genRsa1024().getPrivate(),
            KEYSTORE_PASSWORD.toCharArray(),
            new Certificate[]{CertificateUtils.generateCertificate()});

        // Save the new keystore contents
        this.keyStoreWrapper.store();
    }

    private void mockTrustStoreProperties() {
        Path keystorePath = tempDir.toPath().resolve(KEYSTORE_LOCATION);
        File keystoreFile = keystorePath.toFile();

        when(trustStoreProperties.getType()).thenReturn(KEYSTORE_TYPE);
        when(trustStoreProperties.getLocation()).thenReturn(new FileSystemResource(keystoreFile));
        when(trustStoreProperties.getPassword()).thenReturn(KEYSTORE_PASSWORD);
    }
}
