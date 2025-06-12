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
import com.intel.bkp.core.psgcertificate.PsgCertificateHelper;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidSignatureException;
import com.intel.bkp.crypto.curve.CurvePoint;
import com.intel.bkp.crypto.curve.EcSignatureAlgorithm;
import lombok.RequiredArgsConstructor;

import java.security.PublicKey;

@RequiredArgsConstructor
public class SigmaM2SignatureVerifier {

    private static final String VERIFICATION_FAILED = "Sigma M2 signature verification failed.";

    private final PublicKey publicKey;
    private final SigmaM2Message sigmaM2Message;

    public void verify() {
        final SigmaM2MessageBuilder sigmaM2MessageBuilder = getSigmaM2MessageBuilder();

        final boolean isValid;
        try {
            isValid = PsgCertificateHelper.sigVerify(getSignatureAlgorithm(),
                publicKey, sigmaM2MessageBuilder.getDataForSignature(),
                sigmaM2MessageBuilder.getSignatureBuilder().getCurvePoint());
        } catch (PsgInvalidSignatureException e) {
            throw new ProvisioningGenericException(VERIFICATION_FAILED, e);
        }

        if (!isValid) {
            throw new ProvisioningGenericException(VERIFICATION_FAILED);
        }
    }

    private EcSignatureAlgorithm getSignatureAlgorithm() {
        return EcSignatureAlgorithm.fromCurveSpec(CurvePoint.from(publicKey).getCurveSpec());
    }

    private SigmaM2MessageBuilder getSigmaM2MessageBuilder() {
        return new SigmaM2MessageBuilder()
            .withActor(EndiannessActor.SERVICE)
            .parse(sigmaM2Message.array())
            .withActor(EndiannessActor.FIRMWARE);
    }
}
