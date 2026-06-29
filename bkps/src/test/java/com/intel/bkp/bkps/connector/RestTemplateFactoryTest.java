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

package com.intel.bkp.bkps.connector;

import com.intel.bkp.test.CertificateUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.web.client.RestTemplate;

import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;
import static org.springframework.test.util.ReflectionTestUtils.setField;

@ExtendWith(MockitoExtension.class)
public class RestTemplateFactoryTest {

    private static final String KEYSTORE_PASSWORD = "test";
    private static final String KEYSTORE_TYPE = "PKCS12";
    @Mock
    private SslStoreBundle sslStoreBundle;
    @Mock
    private SslBundle sslBundle;
    @Mock
    private SslBundles sslBundles;
    @InjectMocks
    private RestTemplateFactory sut;

    @Test
    void getCustomRestTemplate_Success() throws Exception {
        // given
        prepareInjectedFields("", 0);
        mockSslBundle();

        // when
        RestTemplate restTemplate = sut.getRestTemplate();

        // then
        assertNotNull(restTemplate, "Rest Template object shouldn't be null");
    }

    @Test
    void getCustomRestTemplate_WithProxySet_Success() throws Exception {
        // given
        prepareInjectedFields("proxy-chain.intel.com", 911);
        mockSslBundle();

        // when
        RestTemplate restTemplate = sut.getRestTemplate();

        // then
        assertNotNull(restTemplate, "Rest Template object shouldn't be null");
    }

    @Test
    void getCustomRestTemplate_WithCrlFlagEnabled_Success() throws Exception {
        // given
        prepareInjectedFields("", 0);
        mockSslBundle();

        // when
        RestTemplate restTemplate = sut.getRestTemplate();

        // then
        assertNotNull(restTemplate, "Rest Template object shouldn't be null");
    }

    private KeyStore initCustomTruststore() throws Exception {
        final KeyStore instance = KeyStore.getInstance(KEYSTORE_TYPE);
        char[] password = KEYSTORE_PASSWORD.toCharArray();
        instance.load(null, password);

        // Add the certificate
        instance.setCertificateEntry("myCert", CertificateUtils.generateCertificate());
        return instance;
    }

    private void prepareInjectedFields(String proxyHost, int proxyPort) {
        setField(sut, "ciphers", new String[]{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"});
        setField(sut, "supportedProtocols", new String[]{"TLSv1.2"});
        setField(sut, "proxyHost", proxyHost);
        setField(sut, "proxyPort", proxyPort);
    }

    private void mockSslBundle() throws Exception {
        final KeyStore store = initCustomTruststore();
        when(sslBundles.getBundle("web-server")).thenReturn(sslBundle);
        when(sslBundle.getStores()).thenReturn(sslStoreBundle);
        when(sslStoreBundle.getKeyStore()).thenReturn(store);
        when(sslStoreBundle.getTrustStore()).thenReturn(store);
        when(sslStoreBundle.getKeyStorePassword()).thenReturn(KEYSTORE_PASSWORD);
    }
}
