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

import com.intel.bkp.bkps.domain.ContextKey;
import com.intel.bkp.bkps.exception.ContextKeyException;
import com.intel.bkp.bkps.repository.ContextKeyRepository;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import javax.crypto.SecretKey;
import java.security.Provider;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class ContextKeyManagerTest {

    private static final String BOUNCYCASTLE_CIPHER_TYPE = "GCM";

    @Mock
    private ContextKeyRepository contextKeyRepository;

    @Mock
    private ContextKeyWrapper contextKeyWrapper;

    @Mock
    private ContextKeySyncService contextKeySyncService;

    @Mock
    private SecretKey secretKey;

    @Mock
    private ContextKey contextKey;

    @Mock
    private UnwrappedContextKey unwrappedContextKey;

    @Mock
    private EncryptionProviderException testException;

    @InjectMocks
    private ContextKeyManager sut;

    @BeforeEach
    void setUp() {
        mockContextKeyInSync();
        mockUnwrappedContextKey();
    }

    @Test
    void get_ContextKeyNotNull_CallInSync() {
        // given
        mockContextKeyNotNull();

        // when
        sut.get();

        // then
        verify(contextKeySyncService).inSync(unwrappedContextKey);
    }

    @Test
    void get_ContextKeyNotNullAndInSync_ReturnContextKey() {
        // given
        mockContextKeyNotNull();
        mockContextKeyInSync();

        // when
        SecretKey result = sut.get();

        // then
        assertEquals(secretKey, result);
    }

    @Test
    void get_ContextKeyIsNull_InitializeContextKey() throws EncryptionProviderException {
        // given
        mockKeyNotPresentInDb();

        // when
        sut.get();

        // then
        verifyInitialization();
    }

    @Test
    void get_ContextKeyNotNullButNotInSync_InitializeContextKey() throws EncryptionProviderException {
        // given
        mockContextKeyNotNull();
        mockContextKeyNotInSync();
        mockKeyNotPresentInDb();

        // when
        sut.get();

        // then
        verifyInitialization();
    }

    @Test
    void get_Initialize_KeyIsPresentInDb_CallUnwrap() throws EncryptionProviderException {
        // given
        mockKeyInDb();

        // when
        sut.get();

        // then
        verify(contextKeyWrapper).unwrap(contextKey);
    }

    @Test
    void getProvider_Success() {
        // when
        Provider result = sut.getProvider();

        // then
        assertTrue(result instanceof BouncyCastleProvider);
    }

    @Test
    void getCipherType_Success() {
        // when
        String result = sut.getCipherType();

        // then
        assertEquals(BOUNCYCASTLE_CIPHER_TYPE, result);
    }

    @Test
    void rotate_Success() throws EncryptionProviderException {
        // when
        sut.rotate();

        // then
        verifyInitialization();
        assertNotNull(sut.getUnwrappedContextKey());
    }

    @Test
    void get_ContextKeyIsNull_ThrowsDuringWrapping() throws EncryptionProviderException {
        // given
        mockKeyNotPresentInDb();
        when(contextKeyWrapper.wrap(any())).thenThrow(testException);

        // when
        assertThrows(ContextKeyException.class, () -> sut.get());
    }

    @Test
    void get_ContextKeyIsNull_ThrowsDuringUnwrapping() throws EncryptionProviderException {
        // given
        mockKeyInDb();
        when(contextKeyWrapper.unwrap(contextKey)).thenThrow(testException);

        // when
        assertThrows(ContextKeyException.class, () -> sut.get());
    }

    private void mockContextKeyNotNull() {
        sut.setUnwrappedContextKey(unwrappedContextKey);
    }

    private void mockKeyInDb() {
        when(contextKeyRepository.getActualContextKey()).thenReturn(Optional.of(contextKey));
    }

    private void mockKeyNotPresentInDb() {
        when(contextKeyRepository.getActualContextKey()).thenReturn(Optional.empty());
    }

    private void mockContextKeyInSync() {
        when(contextKeySyncService.inSync(unwrappedContextKey)).thenReturn(true);
    }

    private void mockContextKeyNotInSync() {
        when(contextKeySyncService.inSync(unwrappedContextKey)).thenReturn(false);
    }

    private void verifyInitialization() throws EncryptionProviderException {
        verify(contextKeyWrapper).wrap(any());
        verify(contextKeyRepository).save(any());
    }

    private void mockUnwrappedContextKey() {
        when(unwrappedContextKey.getSecretKey()).thenReturn(secretKey);
    }
}
