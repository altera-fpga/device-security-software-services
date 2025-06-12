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

package com.intel.bkp.bkps.protocol.sigma.verification;

import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.command.responses.sigma.SigmaEncResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class SigmaEncResponseCounterIvVerifierTest {

    private final byte[] initialIv = new byte[] { 1, 1, 1, 1 };
    private final byte[] responseCounterBytes = new byte[] { 0, 0, 0, 1 };
    private final int responseCounter = ByteBuffer.wrap(responseCounterBytes).getInt();

    @Mock
    private SigmaEncResponse sigmaEncResponse;

    private SigmaEncResponseCounterIvVerifier sut;

    @BeforeEach
    void setUp() {
        sut = new SigmaEncResponseCounterIvVerifier(initialIv, responseCounter, sigmaEncResponse);
    }

    @Test
    void verify_Success() {
        // given
        when(sigmaEncResponse.getMessageResponseCounter()).thenReturn(responseCounterBytes);
        when(sigmaEncResponse.getInitialIv()).thenReturn(initialIv);

        // when
        sut.verify();
    }

    @Test
    void verify_ResponseCounterDoesNotMatch_Throws() {
        // given
        when(sigmaEncResponse.getMessageResponseCounter()).thenReturn(new byte[] { 0, 0, 0, 0 });

        // when
        assertThrows(ProvisioningGenericException.class, () -> sut.verify());
    }

    @Test
    void verify_InitialIvDoesNotMatch_Throws() {
        // given
        when(sigmaEncResponse.getMessageResponseCounter()).thenReturn(responseCounterBytes);
        when(sigmaEncResponse.getInitialIv()).thenReturn(new byte[10]);

        // when
        assertThrows(ProvisioningGenericException.class, () -> sut.verify());
    }
}
