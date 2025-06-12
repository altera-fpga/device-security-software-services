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
import lombok.AllArgsConstructor;

import java.util.Arrays;

import static com.intel.bkp.utils.HexConverter.toHex;

@AllArgsConstructor
public class SigmaM2BkpsPubKeyVerifier {

    private EcdhKeyPair bkpsDhKeyPair;
    private SigmaM2Message sigmaM2Message;

    public void verify() {
        verifyBkpsPubKeyWithSigma(bkpsDhKeyPair, sigmaM2Message.getBkpsDhPubKey());
    }

    private void verifyBkpsPubKeyWithSigma(EcdhKeyPair bkpsKeyPairFromContext, byte[] bkpsPublicKeyFromSigmaM2) {
        final byte[] bkpsPubKey = bkpsKeyPairFromContext.getPublicKey();

        if (!Arrays.equals(bkpsPubKey, bkpsPublicKeyFromSigmaM2)) {
            throw new ProvisioningGenericException(
                String.format("BKPS public key from Sigma M2 does not match public key from context."
                    + "Expected: %s, Actual: %s", toHex(bkpsPubKey), toHex(bkpsPublicKeyFromSigmaM2)));
        }
    }

}
