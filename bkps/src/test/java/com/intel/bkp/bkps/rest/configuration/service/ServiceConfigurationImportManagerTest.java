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

package com.intel.bkp.bkps.rest.configuration.service;

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmImportConfigurationProviderImpl;
import com.intel.bkp.bkps.crypto.importkey.ImportKeyManager;
import com.intel.bkp.bkps.domain.AesKey;
import com.intel.bkp.bkps.domain.ConfidentialData;
import com.intel.bkp.bkps.domain.EncryptedAesImportKey;
import com.intel.bkp.bkps.exception.ServiceImportKeyNotExistException;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.test.RandomUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ServiceConfigurationImportManagerTest {

    private static final String ENCRYPTED_AES_KEY = "00000000";
    private static final String ENCRYPTED_AES_IMPORT_KEY = "22222222";
    private static final String IMPORT_KEY_ALIAS = "alias";
    private static final byte[] DECRYPTED_AES_IMPORT_KEY = RandomUtils.generateRandomBytes(32);
    private static final byte[] DECRYPTED_AES_KEY = RandomUtils.generateRandomBytes(32);

    @Mock
    private ConfidentialData confidentialData;

    @Mock
    private EncryptedAesImportKey encryptedAesKey;

    @Mock
    private AesKey aesKey;

    @Mock
    private ISecurityProvider securityService;

    @Mock
    private ImportKeyManager importKeyManager;

    @Mock
    private AesGcmImportConfigurationProviderImpl decryptionProvider;

    @InjectMocks
    private ServiceConfigurationImportManager sut;

    @BeforeEach
    void setUp() throws EncryptionProviderException {
        when(confidentialData.getEncryptedAesKey()).thenReturn(encryptedAesKey);
        when(encryptedAesKey.getValue()).thenReturn(ENCRYPTED_AES_IMPORT_KEY);
        when(confidentialData.getAesKey()).thenReturn(aesKey);
        when(aesKey.getValue()).thenReturn(ENCRYPTED_AES_KEY);
        when(importKeyManager.exists()).thenReturn(true);
        when(importKeyManager.getImportKeyAlias()).thenReturn(IMPORT_KEY_ALIAS);
        when(securityService.decryptRSA(eq(IMPORT_KEY_ALIAS), any())).thenReturn(DECRYPTED_AES_IMPORT_KEY);
        when(decryptionProvider.decrypt(any())).thenReturn(DECRYPTED_AES_KEY);
    }

    @Test
    void decrypt_VerifyConstructor() {
        // when
        assertDoesNotThrow(() -> new ServiceConfigurationImportManager(securityService, importKeyManager));
    }

    @Test
    void decrypt_VerifyInitialization() {
        // when
        sut.decrypt(confidentialData);

        // then
        verify(importKeyManager).getImportKeyAlias();
        verify(securityService).decryptRSA(eq(IMPORT_KEY_ALIAS), any());
        verify(decryptionProvider).initialize(DECRYPTED_AES_IMPORT_KEY);
    }

    @Test
    void decrypt_VerifyDecryption() throws EncryptionProviderException {
        // given
        when(decryptionProvider.decrypt(fromHex(ENCRYPTED_AES_KEY)))
            .thenReturn(DECRYPTED_AES_KEY);

        // when
        sut.decrypt(confidentialData);

        // then
        verify(aesKey).setValue(toHex(DECRYPTED_AES_KEY));
    }

    @Test
    void decrypt_ThrowsIfImportKeyDoesNotExist() {
        // given
        when(importKeyManager.exists()).thenReturn(false);

        // when

        assertThrows(ServiceImportKeyNotExistException.class, () -> sut.decrypt(confidentialData));
    }

    @Test
    void decrypt_DecryptionProviderThrows() throws EncryptionProviderException {
        // given
        when(decryptionProvider.decrypt(any())).thenThrow(new EncryptionProviderException("test"));

        // when
        assertThrows(BKPBadRequestException.class, () -> sut.decrypt(confidentialData));
    }

    @Test
    void decrypt_NullEncryptedAesKey_Throws() {
        // given
        when(confidentialData.getEncryptedAesKey()).thenReturn(null);

        // when
        assertThrows(BKPBadRequestException.class, () -> sut.decrypt(confidentialData));
    }
}
