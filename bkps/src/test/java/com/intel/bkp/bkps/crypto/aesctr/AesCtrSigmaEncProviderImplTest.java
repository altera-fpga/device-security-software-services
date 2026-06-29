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

package com.intel.bkp.bkps.crypto.aesctr;

import org.bouncycastle.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AesCtrSigmaEncProviderImplTest {

    private static final String SECRET_KEY = "ewq1k4vMPr3QmsYSZf/IkYemIgEipP6hLxvxPJ5moSk=";

    private final byte[] iv = fromHex("80000000000000000000000000000000");

    private AesCtrSigmaEncProviderImpl sut;

    AesCtrSigmaEncProviderImplTest() {
    }

    @BeforeEach
    void setUp() {
        sut = new AesCtrSigmaEncProviderImpl(Base64.getDecoder().decode(SECRET_KEY), () -> iv);
    }

    @Test
    void encrypt_decrypt_Success() throws Exception {
        // given
        byte[] dataToEncrypt = new byte[]{97, 98, 99};

        // when
        final byte[] outputEncrypt = sut.encrypt(dataToEncrypt);
        final byte[] outputDecrypt = sut.decrypt(outputEncrypt);

        // then
        assertNotNull(outputEncrypt);
        assertNotNull(outputDecrypt);
        assertTrue(Arrays.areEqual(dataToEncrypt, outputDecrypt));
    }
}
