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

import com.intel.bkp.bkps.domain.WrappingKey;
import com.intel.bkp.bkps.exception.WrappingKeyException;
import com.intel.bkp.bkps.repository.WrappingKeyRepository;
import com.intel.bkp.core.security.IKeystoreManager;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.crypto.constants.SecurityKeyType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class WrappingKeyManagerTest {

    private static final String GUID = "guid";

    @Mock
    private IKeystoreManager keystoreManager;

    @Mock
    private WrappingKey wrappingKey;

    @Mock
    private ISecurityProvider securityService;

    @Mock
    private WrappingKeyRepository wrappingKeyRepository;

    @InjectMocks
    private WrappingKeyManager sut;

    @BeforeEach
    void setUp() {
        when(wrappingKey.getGuid()).thenReturn(GUID);
    }

    @Test
    void getKey_KeyExists_Success() {
        // given
        mockKeyInDb();
        mockKeyInEnclave();

        // when
        WrappingKey result = sut.getKey();

        // then
        assertEquals(wrappingKey, result);
    }

    @Test
    void getKey_KeyExists_DoesNotCallCreate() {
        // given
        mockKeyInDb();
        mockKeyInEnclave();

        // when
        sut.getKey();

        // then
        verify(securityService, never()).createSecurityObject(any(), any());
    }

    @Test
    void getKey_KeyExistsInDbButNotInEnclave_CreateNew() {
        // given
        mockKeyInDb();
        mockKeyNotPresentInEnclaveThenPresent();
        mockKeyCreatedInDb();

        // when
        WrappingKey result = sut.getKey();

        // then
        verifyKeyCreated();
        assertNotNull(result);
    }

    @Test
    void getKey_KeyDoesNotExist_CreateNew() {
        // given
        mockKeyNotPresentInDb();
        mockKeyCreatedInDb();
        mockKeyCreatedNewInEnclave();

        // when
        sut.getKey();

        // then
        verifyKeyCreated();
    }

    @Test
    void getKey_KeyDoesNotExist_CreatingNewThrows() {
        // given
        mockKeyNotPresentInDb();
        mockKeyCreatedInDb();
        mockKeyWasNotCreatedInEnclave();

        // when

        assertThrows(WrappingKeyException.class, () -> sut.getKey());
    }

    @Test
    void rotate_KeyExists_DeleteFromEnclave() {
        // given
        mockKeyInDb();
        mockKeyInEnclave();

        // when
        sut.rotate();

        // then
        verify(securityService).deleteSecurityObject(GUID);
    }

    @Test
    void rotate_KeyExistsInDbButNotInEnclave_CreateNew() {
        // given
        mockKeyInDb();
        mockKeyNotPresentInEnclave();

        // when
        sut.rotate();

        // then
        verify(securityService, never()).deleteSecurityObject(GUID);
    }

    @Test
    void getSecretKeyFrom_KeyExistsInEnclave_ReturnSecretKey() {
        // when
        sut.getSecretKeyFrom(wrappingKey);

        // then
        verify(securityService).getKeyFromSecurityObject(GUID);
    }

    @Test
    void getProvider_Success() {
        // when
        sut.getProvider();

        // then
        verify(securityService).getProvider();
    }

    @Test
    void getCipherType_Success() {
        // given
        when(securityService.getKeystoreManager()).thenReturn(keystoreManager);

        // when
        sut.getCipherType();

        // then
        verify(securityService).getAesCipherType();
    }

    private void mockKeyInDb() {
        when(wrappingKeyRepository.getActualWrappingKey()).thenReturn(Optional.of(wrappingKey));
    }

    private void mockKeyCreatedInDb() {
        when(wrappingKeyRepository.save(any())).thenReturn(wrappingKey);
    }

    private void mockKeyNotPresentInDb() {
        when(wrappingKeyRepository.getActualWrappingKey()).thenReturn(Optional.empty());
    }

    private void mockKeyInEnclave() {
        when(securityService.existsSecurityObject(GUID)).thenReturn(true);
    }

    private void mockKeyNotPresentInEnclave() {
        when(securityService.existsSecurityObject(GUID)).thenReturn(false);
    }

    private void mockKeyNotPresentInEnclaveThenPresent() {
        when(securityService.existsSecurityObject(any())).thenReturn(false, true);
    }

    private void mockKeyCreatedNewInEnclave() {
        when(securityService.existsSecurityObject(any())).thenReturn(true);
    }

    private void mockKeyWasNotCreatedInEnclave() {
        when(securityService.existsSecurityObject(any())).thenReturn(false);
    }

    private void verifyKeyCreated() {
        verify(securityService).createSecurityObject(eq(SecurityKeyType.AES), any());
        verify(wrappingKeyRepository).save(any());
    }
}
