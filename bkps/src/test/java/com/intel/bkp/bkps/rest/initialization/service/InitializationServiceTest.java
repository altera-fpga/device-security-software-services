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


package com.intel.bkp.bkps.rest.initialization.service;

import com.intel.bkp.bkps.crypto.importkey.ImportKeyManager;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static com.intel.bkp.test.AssertionUtils.verifyExpectedErrorCode;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class InitializationServiceTest {

    @Mock
    private ImportKeyManager importKeyManager;

    @InjectMocks
    private InitializationService sut;

    private void mockImportKeyExists() {
        when(importKeyManager.exists()).thenReturn(true);
    }


    private void mockImportKeyDoesNotExist() {
        when(importKeyManager.exists()).thenReturn(false);
    }

    @Test
    void createServiceImportKey_ServiceImportKeyExistsInDbAndInEnclave_ThrowKeyAlreadyExists() {
        // given
        mockImportKeyExists();

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.createServiceImportKeyPair()
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.IMPORT_KEY_ALREADY_EXISTS);
    }

    @Test
    void createServiceImportKey_CreatesNewServiceImportKey() {
        // given
        mockImportKeyDoesNotExist();

        // when
        sut.createServiceImportKeyPair();

        // then
        verify(importKeyManager).create();
    }

    @Test
    void deleteServiceImportKey_DeletesServiceImportKey() {
        // when
        sut.deleteServiceImportKey();

        // then
        verify(importKeyManager).delete();
    }
}
