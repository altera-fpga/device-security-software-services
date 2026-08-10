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

package com.intel.bkp.bkps.crypto.contextkey;

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmWrappingKeyProviderImpl;
import com.intel.bkp.bkps.domain.ContextKey;
import com.intel.bkp.bkps.domain.WrappingKey;
import com.intel.bkp.bkps.exception.WrappingKeyException;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.dao.DataIntegrityViolationException;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class ContextKeyWrapperTest {

    private static final byte[] SECRET_KEY = new byte[10];
    private static final byte[] CONTEXT_KEY = new byte[32];

    private final EncryptionProviderException testException = new EncryptionProviderException("");

    @Mock
    private DataIntegrityViolationException integrityViolationException;

    @Mock
    private WrappingKeyException wrappingKeyException;

    @Mock
    private WrappingKey wrappingKey;

    @Mock
    private SecretKey secretKey;

    @Mock
    private ContextKey contextKey;

    @Mock
    private AesGcmWrappingKeyProviderImpl aesGcmWrappingProvider;

    @Mock
    private WrappingKeyManager wrappingKeyManager;

    @InjectMocks
    private ContextKeyWrapper sut;

    @BeforeEach
    void setUp() {
        when(secretKey.getEncoded()).thenReturn(SECRET_KEY);
        when(contextKey.decoded()).thenReturn(CONTEXT_KEY);
        when(contextKey.getWrappingKey()).thenReturn(wrappingKey);
        when(wrappingKeyManager.getKey()).thenReturn(wrappingKey);
    }

    @Test
    void wrap_CallsGetWrappingKey() throws Exception {
        // given
        mockContextEncrypt();

        // when
        sut.wrap(secretKey);

        // then
        verify(wrappingKeyManager).getKey();
    }

    @Test
    void wrap_CallsInitializeProvider() throws Exception {
        // given
        mockContextEncrypt();

        // when
        sut.wrap(secretKey);

        // then
        verify(aesGcmWrappingProvider).initialize(wrappingKey);
    }

    @Test
    void wrap_CallsEncrypt() throws Exception {
        // given
        mockContextEncrypt();

        // when
        sut.wrap(secretKey);

        // then
        verify(aesGcmWrappingProvider).encrypt(SECRET_KEY);
    }

    @Test
    void wrap_EncryptThrows() throws Exception {
        // given
        when(aesGcmWrappingProvider.encrypt(SECRET_KEY)).thenThrow(testException);

        // when
        assertThrows(EncryptionProviderException.class, () -> sut.wrap(secretKey));
    }

    @Test
    void wrap_CallsFailsafe() throws Exception {
        // given
        mockContextEncrypt();
        when(wrappingKeyManager.getKey())
            .thenThrow(integrityViolationException)
            .thenThrow(wrappingKeyException)
            .thenReturn(wrappingKey);

        // when
        sut.wrap(secretKey);

        // then
        verify(aesGcmWrappingProvider).encrypt(SECRET_KEY);
    }

    @Test
    void wrap_CallsFailsafeDueToNullResult() throws Exception {
        // given
        mockContextEncrypt();
        when(wrappingKeyManager.getKey())
            .thenReturn(null)
            .thenReturn(null)
            .thenReturn(wrappingKey);

        // when
        sut.wrap(secretKey);

        // then
        verify(aesGcmWrappingProvider).encrypt(SECRET_KEY);
    }

    @Test
    void wrap_FailsafeEndsAfterRetries() {
        // given
        when(wrappingKeyManager.getKey())
            .thenThrow(integrityViolationException)
            .thenThrow(wrappingKeyException)
            .thenThrow(wrappingKeyException);

        // when
        assertThrows(WrappingKeyException.class, () -> sut.wrap(secretKey));
    }

    @Test
    void unwrap_CallInitialize() throws EncryptionProviderException {
        // given
        mockDecryptionResult();

        // when
        sut.unwrap(contextKey);

        // then
        verify(aesGcmWrappingProvider).initialize(wrappingKey);
    }

    @Test
    void unwrap_CallsDecrypt() throws EncryptionProviderException {
        // given
        mockDecryptionResult();

        // when
        sut.unwrap(contextKey);

        // then
        verify(aesGcmWrappingProvider).decrypt(CONTEXT_KEY);
    }

    @Test
    void unwrap_Success() throws EncryptionProviderException {
        // given
        mockDecryptionResult();

        // when
        SecretKey result = sut.unwrap(contextKey);

        // then
        assertNotNull(result);
    }

    @Test
    void unwrap_DecryptThrows() throws EncryptionProviderException {
        // given
        when(aesGcmWrappingProvider.decrypt(CONTEXT_KEY)).thenThrow(testException);

        // when
        assertThrows(EncryptionProviderException.class, () -> sut.unwrap(contextKey));
    }

    private void mockDecryptionResult() throws EncryptionProviderException {
        when(aesGcmWrappingProvider.decrypt(CONTEXT_KEY)).thenReturn(CONTEXT_KEY);
    }

    @SneakyThrows
    private void mockContextEncrypt() {
        when(aesGcmWrappingProvider.encrypt(any())).thenReturn(new byte[]{1, 2, 3});
    }
}
