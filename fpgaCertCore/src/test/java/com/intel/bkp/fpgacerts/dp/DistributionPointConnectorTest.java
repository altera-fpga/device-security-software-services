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

import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockedStatic;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.security.KeyManagementException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

class DistributionPointConnectorTest {

    private static MockedStatic<SSLContext> SSLContextMockStatic;
    private static MockedStatic<SSLConnectionSocketFactory> SSLSocketFactoryMockStatic;
    private static MockedStatic<SSLConnectionSocketFactoryBuilder> SSLSocketFactoryBuilderMockStatic;
    private static MockedStatic<HttpClientConnectionManager> HttpClientConnectionManagerMockStatic;

    @Mock
    private TrustManager[] managers;

    @BeforeAll
    static void prepareStaticMock() {
        SSLContextMockStatic = mockStatic(SSLContext.class);
        SSLSocketFactoryMockStatic = mockStatic(SSLConnectionSocketFactory.class);
        SSLSocketFactoryBuilderMockStatic = mockStatic(SSLConnectionSocketFactoryBuilder.class);
        HttpClientConnectionManagerMockStatic = mockStatic(HttpClientConnectionManager.class);
    }

    @AfterAll
    static void closeStaticMock() {
        SSLContextMockStatic.close();
        SSLSocketFactoryMockStatic.close();
        HttpClientConnectionManagerMockStatic.close();
    }

    @Test
    void constructor_Success() throws KeyManagementException {
        // given
        SSLContext sslContext = mock(SSLContext.class);
        SSLConnectionSocketFactory sslConnectionSocketFactory = mock(SSLConnectionSocketFactory.class);
        SSLConnectionSocketFactoryBuilder sslConnectionSocketFactoryBuilder = mock(SSLConnectionSocketFactoryBuilder.class);
        SSLContextMockStatic.when(() -> SSLContext.getInstance(any())).thenReturn(sslContext);
        doNothing().when(sslContext).init(eq(null), eq(managers), any());
        SSLSocketFactoryBuilderMockStatic.when(SSLConnectionSocketFactoryBuilder::create).thenReturn(sslConnectionSocketFactoryBuilder);
        when(sslConnectionSocketFactoryBuilder
            .setSslContext(eq(sslContext))).thenReturn(sslConnectionSocketFactoryBuilder);
        when(sslConnectionSocketFactoryBuilder
            .setHostnameVerifier(any(DefaultHostnameVerifier.class)))
            .thenReturn(sslConnectionSocketFactoryBuilder);
        when(sslConnectionSocketFactoryBuilder.build()).thenReturn(sslConnectionSocketFactory);

        // when-then
        assertDoesNotThrow(() -> new DistributionPointConnector("", 0, "", managers));
    }
}
