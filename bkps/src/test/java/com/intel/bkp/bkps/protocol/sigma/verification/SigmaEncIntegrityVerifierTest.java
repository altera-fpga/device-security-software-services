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

import com.intel.bkp.bkps.crypto.hmac.HMacSigmaEncProviderImpl;
import com.intel.bkp.command.responses.sigma.SigmaEncResponse;
import com.intel.bkp.command.responses.sigma.SigmaEncResponseBuilder;
import com.intel.bkp.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.crypto.exceptions.EcdhKeyPairException;
import com.intel.bkp.crypto.exceptions.HMacProviderException;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class SigmaEncIntegrityVerifierTest {

    private final byte[] sessionMacKey = EcdhKeyPair.generate().getPrivateKey();

    SigmaEncIntegrityVerifierTest() throws EcdhKeyPairException {
    }

    @Test
    void verify_Success() throws HMacProviderException {
        // given
        SigmaEncResponse sigmaEncResponse = prepareSigmaEncMessageWithCorrectMac();

        // when
        new SigmaEncIntegrityVerifier(sessionMacKey, sigmaEncResponse).verify();
    }

    @Test
    void verify_Throws_DueToWrongHMac() {
        // given
        SigmaEncResponse sigmaEncResponse = prepareSigmaEncMessageWithIncorrectMac();

        // when
        assertThrows(HMacProviderException.class,
            () -> new SigmaEncIntegrityVerifier(sessionMacKey, sigmaEncResponse).verify());
    }

    private SigmaEncResponse prepareSigmaEncMessageWithCorrectMac() throws HMacProviderException {
        SigmaEncResponseBuilder builder = new SigmaEncResponseBuilder();
        builder.setMac(prepareCorrectMac(builder));
        return builder.build();
    }

    private SigmaEncResponse prepareSigmaEncMessageWithIncorrectMac() {
        SigmaEncResponseBuilder builder = new SigmaEncResponseBuilder();
        builder.setMac(prepareIncorrectMac());
        return builder.build();
    }

    private byte[] prepareCorrectMac(SigmaEncResponseBuilder builder) throws HMacProviderException {
        return new HMacSigmaEncProviderImpl(sessionMacKey).getHash(builder.getDataToMac());
    }

    private byte[] prepareIncorrectMac() {
        byte[] incorrectMac = new byte[32];
        ThreadLocalRandom.current().nextBytes(incorrectMac);
        return incorrectMac;
    }
}
