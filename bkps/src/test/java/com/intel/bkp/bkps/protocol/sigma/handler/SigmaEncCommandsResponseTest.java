/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2025 Altera Corporation. All Rights Reserved.
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


package com.intel.bkp.bkps.protocol.sigma.handler;

import com.intel.bkp.bkps.crypto.aesctr.AesCtrSigmaEncProviderImpl;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class SigmaEncCommandsResponseTest {

    private static final byte[] MOCK_DATA = new byte[]{9, 8, 7, 6};
    private static final byte[] EXPECTED = {1, 2, 3, 4};

    @Mock
    private AesCtrSigmaEncProviderImpl encProvider;

    @Mock
    private EncryptionProviderException testException;

    private SigmaEncCommandsResponse sut;

    @BeforeEach
    void setUp() throws EncryptionProviderException {
        when(encProvider.decrypt(MOCK_DATA)).thenReturn(EXPECTED);
        sut = new SigmaEncCommandsResponse(MOCK_DATA);
    }

    @Test
    void decrypt_WithProvider_Success() {
        // when
        byte[] decrypted = sut.decrypt(encProvider);

        // then
        assertEquals(EXPECTED, decrypted);
    }

    @Test
    void decrypt_NoProvider_Throws() {
        // when
        assertThrows(ProvisioningGenericException.class, () -> sut.decrypt(null));
    }

    @Test
    void decrypt_ProviderThrows() throws EncryptionProviderException {
        // given
        when(encProvider.decrypt(any())).thenThrow(testException);

        // when
        assertThrows(ProvisioningGenericException.class, () -> sut.decrypt(encProvider));
    }
}
