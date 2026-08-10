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

package com.intel.bkp.bkps.rest.util;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class HeaderUtilTest {

    private static final String APPLICATION_NAME = "bkpsApp";
    private static final String ALERT_HEADER = "X-" + APPLICATION_NAME + "-alert";
    private static final String PARAM_HEADER = "X-" + APPLICATION_NAME + "-params";
    private static final String ERROR_HEADER = "X-" + APPLICATION_NAME + "-error";

    @Test
    void createAlert_BasicTest_ReturnsProperHeader() {
        // given
        String message = "TestMessage";
        String param = "1";
        List<String> params = Collections.singletonList(param);
        List<String> messages = Collections.singletonList(message);

        // when
        HttpHeaders headers = HeaderUtil.createAlert(message, param);

        // then
        checkResult(headers, messages, params);
    }

    @Test
    void createEntityCreationAlert_BasicTest_ReturnsProperHeader() {
        // given
        String name = "ConfigurationEntity";
        String param = "1";
        List<String> params = Collections.singletonList(param);
        List<String> messages = Collections.singletonList("A new " + name + " is created with identifier " + param);

        // when
        HttpHeaders headers = HeaderUtil.createEntityCreationAlert(name, param);

        // then
        checkResult(headers, messages, params);
    }

    @Test
    void createEntityUpdateAlert_BasicTest_ReturnsProperHeader() {
        // given
        String name = "ConfigurationEntity";
        String param = "1";
        List<String> params = Collections.singletonList(param);
        List<String> messages = Collections.singletonList("A " + name + " is updated with identifier " + param);

        // when
        HttpHeaders headers = HeaderUtil.createEntityUpdateAlert(name, param);

        // then
        checkResult(headers, messages, params);
    }

    @Test
    void createEntityDeletionAlert_BasicTest_ReturnsProperHeader() {
        // given
        String name = "ConfigurationEntity";
        String param = "1";
        List<String> params = Collections.singletonList(param);
        List<String> messages = Collections.singletonList("A " + name + " is deleted with identifier " + param);

        // when
        HttpHeaders headers = HeaderUtil.createEntityDeletionAlert(name, param);

        // then
        checkResult(headers, messages, params);
    }

    @Test
    void createFailureAlert_BasicTest_ReturnsProperHeader() {
        // given
        String name = "Failed to do something";
        List<String> messages = Collections.singletonList(name);

        // when
        HttpHeaders headers = HeaderUtil.createFailureAlert(name);

        // then
        assertEquals(1, headers.entrySet().size());
        assertTrue(headers.containsKey(ERROR_HEADER));
        assertEquals(messages, headers.get(ERROR_HEADER));
    }

    private void checkResult(HttpHeaders headers, List<String> messages, List<String> params) {
        assertEquals(2, headers.entrySet().size());
        assertTrue(headers.containsKey(ALERT_HEADER));
        assertTrue(headers.containsKey(PARAM_HEADER));
        assertEquals(messages, headers.get(ALERT_HEADER));
        assertEquals(params, headers.get(PARAM_HEADER));
    }

}
