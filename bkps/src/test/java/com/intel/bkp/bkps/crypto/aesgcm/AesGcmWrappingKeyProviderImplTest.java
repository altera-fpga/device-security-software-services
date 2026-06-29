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

import com.intel.bkp.bkps.crypto.contextkey.WrappingKeyManager;
import com.intel.bkp.bkps.domain.WrappingKey;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.test.KeyGenUtils;
import org.bouncycastle.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class AesGcmWrappingKeyProviderImplTest {

    private static final SecretKey SECRET_KEY =
        KeyGenUtils.genAesKeyFromBase64("ewq1k4vMPr3QmsYSZf/IkYemIgEipP6hLxvxPJ5moSk=");

    @Mock
    private WrappingKey wrappingKey;

    @Mock
    private WrappingKeyManager wrappingKeyManager;

    @InjectMocks
    private AesGcmWrappingKeyProviderImpl sut;

    @BeforeEach
    void setUp() throws EncryptionProviderException {
        sut.initialize(wrappingKey);
    }

    @Test
    void initialize_CannotBeNull_Throws() {
        // when
        assertThrows(EncryptionProviderException.class, () -> sut.initialize(null));
    }

    @Test
    void encrypt_decrypt_Success() throws Exception {
        // given
        prepareWrappingKeyManager();
        byte[] dataToEncrypt = new byte[]{97, 98, 99};

        // when
        final byte[] outputEncrypt = sut.encrypt(dataToEncrypt);
        final byte[] outputDecrypt = sut.decrypt(outputEncrypt);

        // then
        assertNotNull(outputEncrypt);
        assertNotNull(outputDecrypt);
        assertTrue(Arrays.areEqual(dataToEncrypt, outputDecrypt));
    }

    @Test
    void decrypt_ThrowsEncryptionProviderException() {
        // given
        prepareWrappingKeyManager();

        // when
        assertThrows(EncryptionProviderException.class,
            () -> sut.decrypt(new byte[]{0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
        );
    }

    private void prepareWrappingKeyManager() {
        when(wrappingKeyManager.getSecretKeyFrom(wrappingKey)).thenReturn(SECRET_KEY);
        when(wrappingKeyManager.getProvider()).thenReturn(CryptoUtils.getBouncyCastleProvider());
        when(wrappingKeyManager.getCipherType()).thenReturn("GCM");
    }
}
