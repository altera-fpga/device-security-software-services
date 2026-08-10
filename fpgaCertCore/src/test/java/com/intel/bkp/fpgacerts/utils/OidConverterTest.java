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

package com.intel.bkp.fpgacerts.utils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;

class OidConverterTest {

    private static final String PROFILE_HEX_OID = "6086480186F84D010F06";
    private static final String PROFILE_DECIMAL_OID = "2.16.840.1.113741.1.15.6";
    private static final String TCB_INFO_TYPE_HEX_OID = "6086480186F84D010F0410";
    private static final String TCB_INFO_TYPE_DECIMAL_OID = "2.16.840.1.113741.1.15.4.16";

    @Test
    void fromHexOid_WithProfileOid_Success() {
        // when
        final String result = OidConverter.fromHexOid(PROFILE_HEX_OID);

        // then
        Assertions.assertEquals(PROFILE_DECIMAL_OID, result);
    }

    @Test
    void decimalToHexNotation_WithProfileOid_Success() throws IOException {
        // when
        final String result = OidConverter.decimalToHexNotation(PROFILE_DECIMAL_OID);

        // then
        Assertions.assertEquals(PROFILE_HEX_OID, result);
    }

    @Test
    void decimalToHexNotation_WithTcbInfoKey_Success() throws IOException {
        // when
        final String result = OidConverter.decimalToHexNotation(TCB_INFO_TYPE_DECIMAL_OID);

        // then
        Assertions.assertEquals(TCB_INFO_TYPE_HEX_OID, result);
    }
}
