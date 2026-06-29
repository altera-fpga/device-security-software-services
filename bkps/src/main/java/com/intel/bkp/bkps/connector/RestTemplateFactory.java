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

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.util.Timeout;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;

import static org.apache.hc.client5.http.ssl.HttpsSupport.getDefaultHostnameVerifier;

@Component
@RequiredArgsConstructor
public class RestTemplateFactory {

    private static final String BUNDLE_NAME = "web-server";

    private final SslBundles sslBundles;

    @Value("${server.ssl.ciphers}")
    private String[] ciphers;
    @Value("${server.ssl.enabled-protocols}")
    private String[] supportedProtocols;

    @Value("${application.distribution-point.proxy.host: \"\"}")
    private String proxyHost;
    @Value("${application.distribution-point.proxy.port: 0}")
    private int proxyPort;

    @Bean(name = "distributionPointRestTemplate")
    public RestTemplate getRestTemplate() {
        try {
            return new RestTemplate(clientHttpRequestFactory());
        } catch (Exception e) {
            throw new BeanInitializationException("Failed to create distribution point rest template", e);
        }
    }

    private ClientHttpRequestFactory clientHttpRequestFactory()
        throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        return new HttpComponentsClientHttpRequestFactory(httpClient());
    }

    private HttpClient httpClient() throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException,
            UnrecoverableKeyException {
        final SslStoreBundle webServerBundle = sslBundles.getBundle(BUNDLE_NAME).getStores();
        final KeyStore clientStore = webServerBundle.getKeyStore();

        final KeyStore trustStore = webServerBundle.getTrustStore();

        final var tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(clientStore, webServerBundle.getKeyStorePassword().toCharArray());

        final SSLContext sslcontext = SSLContexts.custom()
            .loadTrustMaterial(trustStore, new TrustAllStrategy())
            .build();

        sslcontext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        final SSLConnectionSocketFactory sslSocketFactory = SSLConnectionSocketFactoryBuilder.create()
            .setSslContext(sslcontext)
            .setCiphers(ciphers)
            .setTlsVersions(supportedProtocols)
            .setHostnameVerifier(getDefaultHostnameVerifier())
            .build();

        final HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
            .setSSLSocketFactory(sslSocketFactory)
            .setDefaultConnectionConfig(getRequestConfig())
            .build();

        final HttpClientBuilder clientBuilder = HttpClients.custom();

        if (StringUtils.isNotEmpty(proxyHost) && proxyPort != 0) {
            clientBuilder.setProxy(new HttpHost(proxyHost, proxyPort));
        }

        return clientBuilder
            .setConnectionManager(cm)
            .evictExpiredConnections()
            .build();
    }

    private ConnectionConfig getRequestConfig() {
        final Timeout timeout = Timeout.ofSeconds(45);
        return ConnectionConfig.custom()
            .setConnectTimeout(timeout)
            .build();
    }
}
