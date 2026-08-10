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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class MdcHelperTest {

    @AfterEach
    void tearDown() {
        MDC.clear();
    }

    @Test
    void get_Success() {
        // when
        String txId = MdcHelper.get();

        // then
        assertNotNull(txId);
    }

    @Test
    void get_WithAvailableTxId_Success() {
        // given
        String generatedTxId = MdcHelper.get();

        // when
        String currentTxId = MdcHelper.get();

        // then
        assertEquals(generatedTxId, currentTxId);
    }

    @Test
    void setFromHeaders_Success() {
        // given
        HttpHeaders headers = new HttpHeaders();
        String generatedTxId = UUID.randomUUID().toString();
        headers.set(ApplicationConstants.TX_ID_HEADER, generatedTxId);

        // when
        MdcHelper.setFromHeaders(headers);

        // then
        assertEquals(generatedTxId, MdcHelper.get());
    }

    @Test
    void setFromHeaders_WithEmptyHeaders_DoNothing() {
        // given
        HttpHeaders headers = new HttpHeaders();

        // when
        MdcHelper.setFromHeaders(headers);

        // then
        assertNull(MDC.get(ApplicationConstants.TX_ID_HEADER));
    }

    @Test
    void setFromHeaders_WithoutTxIdHeader_DoNothing() {
        // given
        HttpHeaders headers = new HttpHeaders();
        headers.set("test", "test");

        // when
        MdcHelper.setFromHeaders(headers);

        // then
        assertNull(MDC.get(ApplicationConstants.TX_ID_HEADER));
    }

    @Test
    void setFromHeaders_WithNullTxIdHeader_DoNothing() {
        // given
        HttpHeaders headers = new HttpHeaders();
        headers.set(ApplicationConstants.TX_ID_HEADER, null);

        // when
        MdcHelper.setFromHeaders(headers);

        // then
        assertNull(MDC.get(ApplicationConstants.TX_ID_HEADER));
    }

    @Test
    void setFromHeaders_WithIdNotUUID_DoNothing() {
        // given
        HttpHeaders headers = new HttpHeaders();
        headers.set(ApplicationConstants.TX_ID_HEADER, "test");

        // when
        MdcHelper.setFromHeaders(headers);

        // then
        assertNull(MDC.get(ApplicationConstants.TX_ID_HEADER));
    }

    @Test
    void isValid_Success() {
        // given
        String txId = UUID.randomUUID().toString();

        // when
        boolean valid = MdcHelper.isValid(txId);

        // then
        assertTrue(valid);
    }

    @Test
    void isValid_WithEmptyTransactionId_Failure() {
        // given
        String txId = "";

        // when
        boolean valid = MdcHelper.isValid(txId);

        // then
        assertFalse(valid);
    }

    @Test
    void isValid_WithNotMatchingPattern_Failure() {
        // given
        String txId = "31m76f85c21-bb8a-4?!@7-bf5a-f8575eb5e2ce";

        // when
        boolean valid = MdcHelper.isValid(txId);

        // then
        assertFalse(valid);
    }

    @Test
    void isValid_WithLengthLessThan_Failure() {
        // given
        String txId = "31m76f85c21-bb8a";

        // when
        boolean valid = MdcHelper.isValid(txId);

        // then
        assertFalse(valid);
    }

    @Test
    void isValid_WithLengthMoreThan_Failure() {
        // given
        String txId = "31m76f85c21-bb8a-46b7-bf5a-f8575eb5e2ce31m76f85c21-bb8a-46b7-bf5a-f8575eb5e2ce";

        // when
        boolean valid = MdcHelper.isValid(txId);

        // then
        assertFalse(valid);
    }

    @Test
    void addSecurityTag_Success() {
        // when
        MdcHelper.addSecurityTag(SecurityLogType.SECURITY_VALIDATION);

        // then
        assertNotNull(MDC.get(ApplicationConstants.SECURITY_KEY));
    }

    @Test
    void removeSecurityTag_Success() {
        // given
        MdcHelper.addSecurityTag(SecurityLogType.SECURITY_VALIDATION);

        // when
        MdcHelper.removeSecurityTag();

        // then
        assertNull(MDC.get(ApplicationConstants.SECURITY_KEY));
    }
}
