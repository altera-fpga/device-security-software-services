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

package com.intel.bkp.bkps.crypto.sealingkey;

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmSealingKeyProviderImpl;
import com.intel.bkp.bkps.crypto.sealingkey.event.SealingKeyTransactionEvent;
import com.intel.bkp.bkps.domain.AesKey;
import com.intel.bkp.bkps.repository.AesKeyRepository;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationEventPublisher;

import javax.crypto.SecretKey;
import java.util.ArrayList;

import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class SealingKeyRotationTransactionTest {

    @Mock
    private SecretKey secretKeyActive;

    @Mock
    private SecretKey secretKeyPending;

    @Mock
    private AesKeyRepository aesKeyRepository;

    @Mock
    private AesKey aesKey;

    @Mock
    private AesGcmSealingKeyProviderImpl encryptionProvider;

    @Mock
    private SealingKeyManager sealingKeyManager;

    @Mock
    private ApplicationEventPublisher eventPublisher;

    @InjectMocks
    private SealingKeyRotationTransaction sut;

    private final ArrayList<AesKey> aesKeys = new ArrayList<>();

    private final byte[] aesEncrypted1 = {1, 0, 1, 1};
    private final byte[] aesEncrypted2 = {1, 1, 1, 1};
    private final byte[] aesDecrypted = {0, 0, 0, 1};
    private final String aesEncrypted1Hex = toHex(aesEncrypted1);
    private final String aesEncrypted2Hex = toHex(aesEncrypted2);

    private final byte[] efusesEncrypted1 = {1, 0, 1, 1, 1, 1};
    private final byte[] efusesEncrypted2 = {1, 1, 1, 1, 0, 0};
    private final byte[] efusesDecrypted = {0, 0, 0, 1, 0, 1};

    @BeforeEach
    void setUp() {
        when(aesKey.getValue()).thenReturn(aesEncrypted1Hex);
    }

    @Test
    void rollbackPendingKey_Success() {
        // when
        sut.rollbackPendingKey(new SealingKeyTransactionEvent());

        // then
        verify(sealingKeyManager).disablePendingKeyAsync();
    }

    @Test
    void logProcessCompleted_Success() {
        // when
        assertDoesNotThrow(() -> sut.logProcessCompleted(new SealingKeyTransactionEvent()));
    }

    @Test
    void reencryptAllAssetsAndActivatePendingKey_Success() throws Exception {
        // given
        mockConfigurations();
        mockEncryptionDecryptionResults();

        // when
        sut.reencryptAllAssetsAndActivatePendingKey(secretKeyActive, secretKeyPending);

        // then

        verifyAssetsReencrypted();

        verify(eventPublisher).publishEvent(any(SealingKeyTransactionEvent.class));
        verify(sealingKeyManager).disableActiveKey();
        verify(sealingKeyManager).activatePendingKey();
    }

    private void mockConfigurations() {
        aesKeys.add(aesKey);
        when(aesKeyRepository.findAll()).thenReturn(aesKeys);
    }

    private void mockEncryptionDecryptionResults() throws EncryptionProviderException {
        when(encryptionProvider.decrypt(aesEncrypted1)).thenReturn(aesDecrypted);
        when(encryptionProvider.encrypt(aesDecrypted)).thenReturn(aesEncrypted2);

        when(encryptionProvider.decrypt(efusesEncrypted1)).thenReturn(efusesDecrypted);
        when(encryptionProvider.encrypt(efusesDecrypted)).thenReturn(efusesEncrypted2);
    }

    private void verifyAssetsReencrypted() {
        verify(encryptionProvider, times(1)).initialize(secretKeyActive);
        verify(encryptionProvider, times(1)).initialize(secretKeyPending);

        verify(aesKey).setValue(aesEncrypted2Hex);
        verify(aesKeyRepository).save(aesKey);
    }
}
