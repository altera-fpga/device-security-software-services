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

import com.intel.bkp.command.responses.sigma.SigmaM2Message;
import com.intel.bkp.command.responses.sigma.SigmaM2MessageBuilder;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.crypto.exceptions.EcdhKeyPairException;
import com.intel.bkp.crypto.exceptions.HMacProviderException;
import com.intel.bkp.crypto.sigma.HMacSigmaProviderImpl;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class SigmaM2IntegrityVerifierTest {

    private final byte[] protocolMacKey = EcdhKeyPair.generate().getPrivateKey();

    SigmaM2IntegrityVerifierTest() throws EcdhKeyPairException {
    }

    @Test
    void verify_Success() throws Exception {
        // given
        SigmaM2Message sigmaM2Message = prepareSigmaM2MessageWithCorrectMac();

        // when
        new SigmaM2IntegrityVerifier(protocolMacKey, sigmaM2Message).verify();
    }

    @Test
    void verify_Throws_DueToWrongHMac() {
        // given
        SigmaM2Message sigmaM2Message = prepareSigmaM2MessageWithIncorrectMac();

        // when

        assertThrows(HMacProviderException.class,
            () -> new SigmaM2IntegrityVerifier(protocolMacKey, sigmaM2Message).verify());
    }

    private SigmaM2Message prepareSigmaM2MessageWithCorrectMac() throws Exception {
        SigmaM2MessageBuilder builder = new SigmaM2MessageBuilder();
        builder.setMac(prepareCorrectMac(builder));
        builder.withActor(EndiannessActor.SERVICE);
        return builder.build();
    }

    private byte[] prepareCorrectMac(SigmaM2MessageBuilder builder) throws Exception {
        final byte[] dataAndSignatureForMac = builder.withActor(EndiannessActor.FIRMWARE).getDataAndSignatureForMac();
        return new HMacSigmaProviderImpl(protocolMacKey).getHash(dataAndSignatureForMac);
    }

    private SigmaM2Message prepareSigmaM2MessageWithIncorrectMac() {
        SigmaM2MessageBuilder builder = new SigmaM2MessageBuilder();
        builder.withActor(EndiannessActor.SERVICE).setMac(prepareIncorrectMac());
        return builder.build();
    }

    private byte[] prepareIncorrectMac() {
        byte[] incorrectMac = new byte[48];
        ThreadLocalRandom.current().nextBytes(incorrectMac);
        return incorrectMac;
    }
}
