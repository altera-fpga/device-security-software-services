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

package com.intel.bkp.fpgacerts.dp;

import com.intel.bkp.fpgacerts.exceptions.ConnectionException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.util.Timeout;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.util.Optional;

import static org.apache.hc.client5.http.ssl.HttpsSupport.getDefaultHostnameVerifier;

@Slf4j
public class DistributionPointConnector implements IDistributionPointConnector, AutoCloseable {

    private CloseableHttpClient client;
    private String mainPath;

    public DistributionPointConnector(final String proxyHost,
                                      final Integer proxyPort,
                                      final String mainPath,
                                      final TrustManager[] trustStore) {
        try {
            final SSLContext sslcontext = SSLContext.getInstance("TLS");
            sslcontext.init(null, trustStore, new SecureRandom());
            this.client = httpClient(proxyHost, proxyPort, sslcontext);
            this.mainPath = mainPath;
        } catch (NoSuchAlgorithmException | KeyManagementException | UnrecoverableKeyException | KeyStoreException e) {
            throw new ConnectionException("Failed to set up distribution point connection", e);
        }
    }

    public DistributionPointConnector(final String proxyHost,
                                      final Integer proxyPort,
                                      final String mainPath,
                                      final SSLContext sslContext) {
        try {
            this.client = httpClient(proxyHost, proxyPort, sslContext);
            this.mainPath = mainPath;
        } catch (NoSuchAlgorithmException | KeyManagementException | UnrecoverableKeyException | KeyStoreException e) {
            throw new ConnectionException("Failed to set up distribution point connection", e);
        }
    }

    public Optional<byte[]> tryGetBytes(String url) {
        try {
            URL originalUrl = new URL(url);
            String originalDomain = originalUrl.getProtocol() + "://" + originalUrl.getAuthority();
            URL expectedUrl = new URL(mainPath);
            String expectedDomain = expectedUrl.getProtocol() + "://" + expectedUrl.getAuthority();
            String validUrl = url;
            // Replace only if the domains are different
            if (!originalDomain.equals(expectedDomain)) {
                validUrl = originalUrl.toString().replaceFirst(originalDomain, expectedDomain);
            }

            log.info("Performing request to: {}", validUrl);
            final HttpGet httpGet = new HttpGet(validUrl);

            // Preferred in HttpClient 5.x: use a response handler so resources are auto-released
            final HttpClientResponseHandler<Optional<byte[]>> handler = (ClassicHttpResponse response) -> {
                final int code = response.getCode();
                if (code == 200) {
                    if (response.getEntity() == null) {
                        return Optional.empty();
                    }
                    // EntityUtils consumes the entity and releases the connection
                    return Optional.of(EntityUtils.toByteArray(response.getEntity()));
                } else {
                    log.error("Request status code: {}", code);
                    return Optional.empty();
                }
            };
            return client.execute(httpGet, handler);
        } catch (MalformedURLException urlException) {
            log.error("URL path \"%s\" to be fetched is malformed.".formatted(url), urlException);
            return Optional.empty();
        } catch (Exception e) {
            log.error("Failed to get http response.", e);
            return Optional.empty();
        }
    }

    private CloseableHttpClient httpClient(final String proxyHost,
                                           final Integer proxyPort,
                                           final SSLContext sslcontext)
        throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException {

        final SSLConnectionSocketFactory sslSocketFactory = SSLConnectionSocketFactoryBuilder.create()
            .setSslContext(sslcontext)
            .setHostnameVerifier(getDefaultHostnameVerifier())
            .build();

        final HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
            .setSSLSocketFactory(sslSocketFactory)
            .setDefaultConnectionConfig(getRequestConfig())
            .build();

        final HttpClientBuilder clientBuilder = HttpClients.custom();

        if (StringUtils.isNotEmpty(proxyHost) && proxyPort != null && proxyPort != 0) {
            clientBuilder.setProxy(new HttpHost(proxyHost, proxyPort));
        }

        return clientBuilder
            .setConnectionManager(cm)
            .evictExpiredConnections()
            .build();
    }

    @Override
    public void close() throws Exception {
        log.debug("Closing HTTP client...");
        client.close();
        client = null;
    }

    private ConnectionConfig getRequestConfig() {
        final Timeout timeout = Timeout.ofSeconds(45);
        return ConnectionConfig.custom()
            .setConnectTimeout(timeout)
            .build();
    }
}
