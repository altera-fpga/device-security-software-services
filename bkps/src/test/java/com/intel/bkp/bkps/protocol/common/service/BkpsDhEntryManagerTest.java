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

package com.intel.bkp.bkps.protocol.common.service;

import com.intel.bkp.bkps.domain.SigningKeyEntity;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.exception.SigningKeyNotExistException;
import com.intel.bkp.bkps.rest.initialization.service.SigningKeyRepositoryService;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.test.KeyGenUtils;
import com.intel.bkp.test.SigningUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class BkpsDhEntryManagerTest {

    @Mock
    private SigningKeyRepositoryService signingKeyRepositoryService;

    @Mock
    private ISecurityProvider securityService;

    @Mock
    SigningKeyEntity signingKeyEntity;

    private BkpsDhEntryManager sut;

    private static final byte[] TEST_DATA = new byte[]{1, 2, 3, 4};

    @BeforeEach
    void prepare() {
        sut = new BkpsDhEntryManager(signingKeyRepositoryService, securityService);
    }


    @Test
    void getDhEntry_Success() {
        // given
        String guid = UUID.randomUUID().toString();
        KeyPair ecKey = KeyGenUtils.genEc384();
        assert ecKey != null;
        when(signingKeyEntity.getName()).thenReturn(guid);
        when(signingKeyRepositoryService.getActiveSigningKey()).thenReturn(signingKeyEntity);
        byte[] signedData = SigningUtils.signEcData(
            "testData".getBytes(), ecKey.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA
        );
        when(securityService.signObject(any(), anyString())).thenReturn(signedData);

        // when
        byte[] result = sut.getDhEntry(TEST_DATA);

        // then
        assertTrue(result.length > 0);
        verify(signingKeyRepositoryService).getActiveSigningKey();
        verify(securityService).signObject(any(), anyString());
    }

    @Test
    void getDhEntry_WithMissingActiveSigningKey_Throws() {
        // given
        when(signingKeyRepositoryService.getActiveSigningKey()).thenThrow(SigningKeyNotExistException.class);

        // when-then
        assertThrows(ProvisioningGenericException.class, () -> sut.getDhEntry(TEST_DATA));
    }
}
