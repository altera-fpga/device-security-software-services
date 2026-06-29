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

package com.intel.bkp.bkps.interceptor;

import com.intel.bkp.core.utils.ApplicationConstants;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.MDC;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
public class LoggingHandlerInterceptorTest {

    @Mock
    HttpServletRequest request;

    @Mock
    HttpServletResponse response;

    @Mock
    Object handler;

    private final LoggingHandlerInterceptor sut = new LoggingHandlerInterceptor();

    @Test
    void preHandle_WithTransactionIdHeaderNotSet_GeneratesNewTransactionId() {
        // when
        boolean result = sut.preHandle(request, response, handler);

        // then
        assertTrue(result);
        assertNotNull(MDC.get(ApplicationConstants.TX_ID_KEY));
    }

    @Test
    void preHandle_WithTransactionIdHeaderSet_UsesExistingTransactionId() {
        // given
        String txId = UUID.randomUUID().toString();
        Mockito.when(request.getHeader(ArgumentMatchers.anyString())).thenReturn(txId);

        // when
        boolean result = sut.preHandle(request, response, handler);

        // then
        assertTrue(result);
        assertEquals(txId, MDC.get(ApplicationConstants.TX_ID_KEY));
    }

    @Test
    void preHandle_TestWithAllMethods_ShouldCleanStoresKeys() {
        // given
        String txId = UUID.randomUUID().toString();
        Mockito.when(request.getHeader(ArgumentMatchers.anyString())).thenReturn(txId);

        // when
        sut.preHandle(request, response, handler);
        assertEquals(txId, MDC.get(ApplicationConstants.TX_ID_KEY));
        sut.afterConcurrentHandlingStarted(request, response, handler);
        sut.afterCompletion(request, response, handler, null);

        // then
        assertNull(MDC.get(ApplicationConstants.TX_ID_KEY), txId);
    }
}
