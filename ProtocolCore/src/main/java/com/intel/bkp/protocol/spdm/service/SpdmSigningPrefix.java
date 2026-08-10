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

package com.intel.bkp.protocol.spdm.service;

import lombok.extern.slf4j.Slf4j;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

@Slf4j
public class SpdmSigningPrefix {

    private static final byte[] SPDM_PREFIX = new byte[]{
        'd', 'm', 't', 'f', '-', 's', 'p', 'd', 'm', '-', 'v', '1', '.', '2', '.', '*',
        'd', 'm', 't', 'f', '-', 's', 'p', 'd', 'm', '-', 'v', '1', '.', '2', '.', '*',
        'd', 'm', 't', 'f', '-', 's', 'p', 'd', 'm', '-', 'v', '1', '.', '2', '.', '*',
        'd', 'm', 't', 'f', '-', 's', 'p', 'd', 'm', '-', 'v', '1', '.', '2', '.', '*'
    };

    private static final String SPDM_REQUESTER_CONTEXT = "requester-";
    private static final int COMBINED_SPDM_PREFIX_LEN = 100;

    public static byte[] getPrefix(String context) {
        final byte[] spdmRequesterContextBytes = SPDM_REQUESTER_CONTEXT.getBytes(StandardCharsets.UTF_8);
        final byte[] contextBytes = context.getBytes(StandardCharsets.UTF_8);

        final int spdmContextPosition = COMBINED_SPDM_PREFIX_LEN
            - spdmRequesterContextBytes.length - contextBytes.length;

        return ByteBuffer.allocate(COMBINED_SPDM_PREFIX_LEN)
            .put(SPDM_PREFIX)
            .put((byte) 0)
            .position(spdmContextPosition)
            .put(spdmRequesterContextBytes)
            .put(contextBytes)
            .array();
    }
}
