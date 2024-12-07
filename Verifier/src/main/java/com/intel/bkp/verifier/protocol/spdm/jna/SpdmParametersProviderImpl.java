/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2024 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.verifier.protocol.spdm.jna;

import com.intel.bkp.protocol.spdm.jna.model.SpdmParametersProvider;
import com.intel.bkp.protocol.spdm.jna.model.Uint32;
import com.intel.bkp.protocol.spdm.jna.model.Uint8;
import com.intel.bkp.verifier.service.certificate.AppContext;

import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_MEASUREMENT_SPECIFICATION_DMTF;

public class SpdmParametersProviderImpl implements SpdmParametersProvider {

    @Override
    public Uint8 ctExponent() {
        final AppContext appContext = AppContext.instance();
        return new Uint8(appContext.getLibConfig().getLibSpdmParams().getCtExponent());
    }

    @Override
    public Uint8 measurementSpec() {
        return new Uint8(SPDM_MEASUREMENT_SPECIFICATION_DMTF);
    }

    @Override
    public Uint32 baseAsymAlgo() {
        return new Uint32(SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384);
    }

    @Override
    public Uint32 baseHashAlgo() {
        return new Uint32(SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384);
    }
}
