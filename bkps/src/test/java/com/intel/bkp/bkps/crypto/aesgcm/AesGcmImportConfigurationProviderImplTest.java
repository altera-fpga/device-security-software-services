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

package com.intel.bkp.bkps.crypto.aesgcm;

import com.intel.bkp.test.RandomUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import java.nio.ByteOrder;
import java.security.Provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
public class AesGcmImportConfigurationProviderImplTest {

    private static final byte[] SECRET_KEY = RandomUtils.generateRandomBytes(32);

    private final AesGcmImportConfigurationProviderImpl sut = new AesGcmImportConfigurationProviderImpl();

    @BeforeEach
    void setUp() {
        sut.initialize(SECRET_KEY);
    }

    @Test
    void getSecretKey() {
        // when
        SecretKey result = sut.getSecretKey();

        // then
        assertArrayEquals(SECRET_KEY, result.getEncoded());
    }

    @Test
    void getProvider() {
        // when
        Provider result = sut.getProvider();

        // then
        assertEquals(BouncyCastleProvider.class, result.getClass());
    }

    @Test
    void getCipherType() {
        // when
        String result = sut.getCipherType();

        // then
        assertEquals("GCM", result);
    }

    @Test
    void getByteOrder() {
        // given
        ByteOrder expected = ByteOrder.BIG_ENDIAN;

        // when
        ByteOrder output = sut.getByteOrder();

        // then
        assertEquals(expected, output);
    }
}
