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

package com.intel.bkp.bkps.utils;

import com.intel.bkp.core.utils.ApplicationConstants;
import com.intel.bkp.core.utils.SecurityLogType;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class MdcHelper {

    public static String get() {
        return Optional.ofNullable(MDC.get(ApplicationConstants.TX_ID_KEY)).orElseGet(MdcHelper::create);
    }

    public static String create() {
        String transactionId = UUID.randomUUID().toString();
        add(transactionId);
        return transactionId;
    }

    public static void add(String transactionId) {
        MDC.put(ApplicationConstants.TX_ID_KEY, transactionId);
    }

    public static void setFromHeaders(HttpHeaders headers) {
        if (!headers.isEmpty() && headers.containsKey(ApplicationConstants.TX_ID_HEADER)) {
            List<String> txList = headers.get(ApplicationConstants.TX_ID_HEADER);
            if (txList != null && !txList.isEmpty()) {
                String transactionId = txList.get(txList.size() - 1);
                if (isValid(transactionId)) {
                    add(transactionId);
                }
            }
        }
    }

    public static boolean isValid(String transactionId) {
        return StringUtils.isNotEmpty(transactionId)
            && transactionId.matches(ApplicationConstants.UUID_PATTERN)
            && transactionId.length() > 30
            && transactionId.length() < 40;
    }

    public static void addSecurityTag(SecurityLogType msg) {
        MDC.put(ApplicationConstants.SECURITY_KEY, msg.name());
    }

    public static void removeSecurityTag() {
        MDC.remove(ApplicationConstants.SECURITY_KEY);
    }
}
