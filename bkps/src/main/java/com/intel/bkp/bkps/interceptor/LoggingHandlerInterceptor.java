/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2024 Intel Corporation. All Rights Reserved.
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

import com.intel.bkp.bkps.utils.MdcHelper;
import com.intel.bkp.core.utils.ApplicationConstants;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.slf4j.MDC;
import org.springframework.web.servlet.AsyncHandlerInterceptor;

import java.util.HashSet;
import java.util.Set;

public class LoggingHandlerInterceptor implements AsyncHandlerInterceptor {

    private final ThreadLocal<Set<String>> storedKeys = ThreadLocal.withInitial(HashSet::new);

    @Override
    public boolean preHandle(HttpServletRequest request, @NonNull HttpServletResponse response,
                             @NonNull Object handler) {
        final String transactionIdHeader = request.getHeader(ApplicationConstants.TX_ID_HEADER);
        final String verifiedTransactionId;

        if (MdcHelper.isValid(transactionIdHeader)) {
            verifiedTransactionId = transactionIdHeader;
            MdcHelper.add(verifiedTransactionId);
        } else {
            verifiedTransactionId = MdcHelper.create();
        }

        storedKeys.get().add(ApplicationConstants.TX_ID_KEY);

        response.setHeader(ApplicationConstants.TX_ID_HEADER, verifiedTransactionId);

        return true;
    }

    @Override
    public void afterConcurrentHandlingStarted(@NonNull HttpServletRequest request,
                                               @NonNull HttpServletResponse response,
                                               @NonNull Object handler) {
        // request ended on current thread remove properties
        removeKeys();
    }

    @Override
    public void afterCompletion(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                @NonNull Object handler, Exception ex) {
        removeKeys();
    }

    private void removeKeys() {
        for (String key : storedKeys.get()) {
            MDC.remove(key);
        }
        storedKeys.remove();
    }
}
