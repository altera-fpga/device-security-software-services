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

package com.intel.bkp.bkps.crypto.importkey;

import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.crypto.constants.SecurityKeyType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.intel.bkp.test.AssertionUtils.verifyExpectedErrorCode;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class ImportKeyManagerTest {

    @Mock
    private ISecurityProvider securityService;

    @InjectMocks
    private ImportKeyManager sut;

    private static final String IMPORT_KEY_ALIAS = ImportKeyManager.IMPORT_KEY_ALIAS;

    @Test
    void create_Success() {
        // given
        mockImportKeyCreatedSuccessfully();

        // when
        sut.create();

        // then
        verify(securityService).createSecurityObject(eq(SecurityKeyType.RSA), eq(IMPORT_KEY_ALIAS));
    }

    @Test
    void create_NotCreatedSuccessfully_Throws() {
        // given
        mockImportKeyWasNotCreated();

        // when-then
        final BKPInternalServerException exception = assertThrows(BKPInternalServerException.class,
            () -> sut.create()
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.FAILED_TO_SAVE_IMPORT_KEY_IN_SECURITY_ENCLAVE);
    }

    @Test
    void delete_Success() {
        // when
        sut.delete();

        // then
        verify(securityService).deleteSecurityObject(IMPORT_KEY_ALIAS);
    }

    @Test
    void exists_ExistsInSecurityEnclave_ReturnsTrue() {
        // given
        mockImportKeyExistsInSecurityEnclave();

        // when
        boolean result = sut.exists();

        // then
        assertTrue(result);
    }

    @Test
    void exists_DoesNotExistInSecurityEnclave_ReturnsFalse() {
        // given
        mockImportKeyDoesNotExistInSecurityEnclave();

        // when
        boolean result = sut.exists();

        // then
        assertFalse(result);
    }

    @Test
    void getImportKeyAlias_Success() {
        // when
        String result = sut.getImportKeyAlias();

        // then
        assertEquals(IMPORT_KEY_ALIAS, result);
    }

    @Test
    void getPublicKey_Success() {
        // given
        byte[] expectedPubKey = new byte[100];
        when(securityService.getPubKeyFromSecurityObject(IMPORT_KEY_ALIAS)).thenReturn(expectedPubKey);

        // when
        byte[] result = sut.getPublicKey();

        // then
        assertArrayEquals(expectedPubKey, result);
    }

    private void mockImportKeyCreatedSuccessfully() {
        when(securityService.existsSecurityObject(IMPORT_KEY_ALIAS)).thenReturn(true);
    }

    private void mockImportKeyWasNotCreated() {
        when(securityService.existsSecurityObject(IMPORT_KEY_ALIAS)).thenReturn(false);
    }

    private void mockImportKeyExistsInSecurityEnclave() {
        when(securityService.existsSecurityObject(IMPORT_KEY_ALIAS)).thenReturn(true);
    }

    private void mockImportKeyDoesNotExistInSecurityEnclave() {
        when(securityService.existsSecurityObject(IMPORT_KEY_ALIAS)).thenReturn(false);
    }

}
