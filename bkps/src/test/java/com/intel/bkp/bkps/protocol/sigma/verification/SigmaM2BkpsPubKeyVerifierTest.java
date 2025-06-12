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
import com.intel.bkp.command.responses.sigma.SigmaM2Message;
import com.intel.bkp.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.crypto.exceptions.EcdhKeyPairException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
public class SigmaM2BkpsPubKeyVerifierTest {

    @Mock
    private SigmaM2Message sigmaM2Message;

    private final EcdhKeyPair bkpsDhKeyPair = EcdhKeyPair.generate();

    SigmaM2BkpsPubKeyVerifierTest() throws EcdhKeyPairException {
    }

    @Test
    void verify_Success() {
        // given
        prepareSigmaM2Message(true);

        // when
        new SigmaM2BkpsPubKeyVerifier(bkpsDhKeyPair, sigmaM2Message).verify();
    }

    @Test
    void verify_Throws_DueToWrongBkpsPubKey() {
        // given
        prepareSigmaM2Message(false);

        // when
        assertThrows(ProvisioningGenericException.class,
            () -> new SigmaM2BkpsPubKeyVerifier(bkpsDhKeyPair, sigmaM2Message).verify());
    }

    private void prepareSigmaM2Message(boolean isCorrect) {
        Mockito.when(sigmaM2Message.getBkpsDhPubKey())
            .thenReturn(isCorrect
                        ? bkpsDhKeyPair.getPublicKey()
                        : new byte[] { 1, 2, 3, 4 });
    }
}
