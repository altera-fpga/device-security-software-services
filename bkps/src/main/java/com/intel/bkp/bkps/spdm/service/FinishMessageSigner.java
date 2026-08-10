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

package com.intel.bkp.bkps.spdm.service;

import com.intel.bkp.bkps.rest.initialization.service.SigningKeyRepositoryService;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.crypto.curve.CurvePoint;
import com.intel.bkp.protocol.spdm.exceptions.SpdmRuntimeException;
import com.intel.bkp.protocol.spdm.jna.SignatureProvider;
import com.intel.bkp.protocol.spdm.service.SpdmSigningPrefix;
import com.intel.bkp.utils.HexConverter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.ByteBuffer;

import static com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType.SECP384R1;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_SIGNATURE_FINISH_SIGNING_CONTEXT;
import static com.intel.bkp.utils.HexConverter.toHex;

@RequiredArgsConstructor
@Service
@Transactional(isolation = Isolation.SERIALIZABLE)
@Slf4j
public class FinishMessageSigner implements SignatureProvider {

    private final SigningKeyRepositoryService signingKeyRepositoryService;
    private final ISecurityProvider securityProvider;

    @Override
    public byte[] sign(byte[] data, int reqBaseAsymAlg, int baseHashAlgo) {
        if (SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 != reqBaseAsymAlg) {
            throw new SpdmRuntimeException("Requested signing algorithm not supported.\n"
                + "Requested: %s, Supported: %s".formatted(toHex(reqBaseAsymAlg),
                toHex(SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384)));
        }

        if (SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 != baseHashAlgo) {
            throw new SpdmRuntimeException("Requested hash algorithm not supported.\n"
                + "Requested: %s, Supported: %s".formatted(toHex(baseHashAlgo),
                toHex(SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384)));
        }

        final byte[] combinedSpdmPrefix = SpdmSigningPrefix.getPrefix(SPDM_SIGNATURE_FINISH_SIGNING_CONTEXT);
        log.trace("SPDM FINISH - combined SPDM prefix: {}", HexConverter.toHex(combinedSpdmPrefix));

        final byte[] messageHash = DigestUtils.sha384(data);

        log.trace("SPDM FINISH - message hash: {}", toHex(messageHash));

        final byte[] dataToSign = ByteBuffer.allocate(combinedSpdmPrefix.length + messageHash.length)
            .put(combinedSpdmPrefix)
            .put(messageHash)
            .array();

        final String signingKeyGuid = signingKeyRepositoryService.getActiveSigningKey().getName();
        final byte[] signature = securityProvider.signObject(dataToSign, signingKeyGuid);

        final CurvePoint curvePoint = CurvePoint.fromSignature(signature, SECP384R1);
        final byte[] signatureForSpdm = curvePoint.getAlignedDataToSize();

        log.trace("Data to sign:\n{}\nSignature full:\n{}\nSignature RAW RS:\n{}\n",
            toHex(dataToSign), toHex(signature), toHex(signatureForSpdm));

        return signatureForSpdm;
    }
}
