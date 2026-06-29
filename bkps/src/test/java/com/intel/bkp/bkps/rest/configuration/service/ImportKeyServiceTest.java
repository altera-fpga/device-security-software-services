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

import com.intel.bkp.bkps.crypto.importkey.ImportKeyManager;
import com.intel.bkp.bkps.exception.ServiceImportKeyNotExistException;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.crypto.pem.PemFormatHeader;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static com.intel.bkp.test.AssertionUtils.verifyExpectedErrorCode;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class ImportKeyServiceTest {

    @Mock
    private ImportKeyManager importKeyManager;

    @InjectMocks
    private ImportKeyService sut;

    @Test
    void getServiceImportPublicKey_ReturnsPublicKey() throws NoSuchAlgorithmException {
        // given
        final byte[] publicKey = preparePublicKey();
        mockImportKeyExists();
        when(importKeyManager.getPublicKey()).thenReturn(publicKey);

        // when
        String encodedKey = sut.getServiceImportPublicKey();

        // then
        MatcherAssert.assertThat(encodedKey, CoreMatchers.containsString(PemFormatHeader.PUBLIC_KEY.getBegin()));
        MatcherAssert.assertThat(encodedKey, CoreMatchers.containsString(PemFormatHeader.PUBLIC_KEY.getEnd()));
    }

    @Test
    void getServiceImportPublicKey_WithoutImportKey_ThrowsImportKeyNotExists() {
        // given
        mockImportKeyDoesNotExist();

        // when-then
        final ServiceImportKeyNotExistException exception = assertThrows(ServiceImportKeyNotExistException.class,
            () -> sut.getServiceImportPublicKey()
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.IMPORT_KEY_DOES_NOT_EXIST);
    }

    @Test
    void getServiceImportPublicKey_ThrowsExceptionDueToKeyIsEmpty() {
        // given
        final byte[] publicKey = preparePublicKeyEmpty();
        mockImportKeyExists();
        when(importKeyManager.getPublicKey()).thenReturn(publicKey);

        // when-then
        final BKPInternalServerException exception = assertThrows(BKPInternalServerException.class,
            () -> sut.getServiceImportPublicKey()
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.UNABLE_TO_RETRIEVE_PUBLIC_KEY);
    }

    private byte[] preparePublicKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair key = keyGen.generateKeyPair();
        return key.getPublic().getEncoded();
    }

    private byte[] preparePublicKeyEmpty() {
        return new byte[0];
    }

    private void mockImportKeyExists() {
        when(importKeyManager.exists()).thenReturn(true);
    }

    private void mockImportKeyDoesNotExist() {
        when(importKeyManager.exists()).thenReturn(false);
    }
}
