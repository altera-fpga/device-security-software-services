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
import com.intel.bkp.command.responses.sigma.SigmaM2MessageBuilder;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PublicKey;

import static com.intel.bkp.bkps.protocol.sigma.SigmaM2TestUtil.getPublicKeyMatchingRealSigmaM2;
import static com.intel.bkp.bkps.protocol.sigma.SigmaM2TestUtil.getRealSigmaM2WithoutHeaderFm;
import static com.intel.bkp.bkps.protocol.sigma.SigmaM2TestUtil.getRealSigmaM2WithoutHeaderS10;
import static com.intel.bkp.crypto.constants.CryptoConstants.EC_CURVE_SPEC_256;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class SigmaM2SignatureVerifierTest {

    private final PublicKey mismatchedPublicKey = CryptoUtils.genEcdhBC().getPublic();
    private final PublicKey wrongCurvePublicKey = CryptoUtils.genEcdsaBC(EC_CURVE_SPEC_256).getPublic();
    private final PublicKey matchingPublicKey = getPublicKeyMatchingRealSigmaM2();
    private final SigmaM2Message realSigmaM2MessageS10 = getRealSigmaM2MessageS10();
    private final SigmaM2Message realSigmaM2MessageFm = getRealSigmaM2MessageFm();

    SigmaM2SignatureVerifierTest() throws KeystoreGenericException {}

    @Test
    void verify_WithRealDataS10_Success() {
        // given
        final var sut = prepareSigmaM2SignatureVerifier(matchingPublicKey, realSigmaM2MessageS10);

        // when-then
        assertDoesNotThrow(sut::verify);
    }

    @Test
    void verify_WithRealDataFm_Success() {
        // given
        final var sut = prepareSigmaM2SignatureVerifier(matchingPublicKey, realSigmaM2MessageFm);

        // when-then
        assertDoesNotThrow(sut::verify);
    }

    @Test
    void verify_MismatchedPublicKeyS10_Throws() {
        // given
        final var sut = prepareSigmaM2SignatureVerifier(mismatchedPublicKey, realSigmaM2MessageS10);

        // when-then
        assertThrows(ProvisioningGenericException.class, sut::verify);
    }

    @Test
    void verify_MismatchedPublicKeyFm_Throws() {
        // given
        final var sut = prepareSigmaM2SignatureVerifier(mismatchedPublicKey, realSigmaM2MessageFm);

        // when-then
        assertThrows(ProvisioningGenericException.class, sut::verify);
    }

    @Test
    void verify_UnexpectedPublicKeyCurveS10_Throws() {
        // given
        final var sut = prepareSigmaM2SignatureVerifier(wrongCurvePublicKey, realSigmaM2MessageS10);

        // when-then
        assertThrows(ProvisioningGenericException.class, sut::verify);
    }

    @Test
    void verify_UnexpectedPublicKeyCurveFm_Throws() {
        // given
        final var sut = prepareSigmaM2SignatureVerifier(wrongCurvePublicKey, realSigmaM2MessageFm);

        // when-then
        assertThrows(ProvisioningGenericException.class, sut::verify);
    }

    private SigmaM2SignatureVerifier prepareSigmaM2SignatureVerifier(PublicKey publicKey, SigmaM2Message sigmaM2) {
        return new SigmaM2SignatureVerifier(publicKey, sigmaM2);
    }

    @SneakyThrows
    private SigmaM2Message getRealSigmaM2MessageS10() {
        return getRealM2Internal(getRealSigmaM2WithoutHeaderS10());
    }

    @SneakyThrows
    private SigmaM2Message getRealSigmaM2MessageFm() {
        return getRealM2Internal(getRealSigmaM2WithoutHeaderFm());
    }

    private SigmaM2Message getRealM2Internal(byte[] realSigmaM2) {
        return new SigmaM2MessageBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(realSigmaM2)
            .withActor(EndiannessActor.SERVICE)
            .build();
    }
}
