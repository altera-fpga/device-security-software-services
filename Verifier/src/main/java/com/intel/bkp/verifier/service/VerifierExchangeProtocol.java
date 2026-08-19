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

package com.intel.bkp.verifier.service;

import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.model.dto.VerifierExchangeResponseDTO;
import static com.intel.bkp.verifier.model.VerifierExchangeResponse.ERROR;
import com.intel.bkp.verifier.transport.model.TransportLayer;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class VerifierExchangeProtocol {
    protected byte[] getChipID = new byte[]{0x12, 0x00, 0x00, 0x00};

    public int createSubKeyInternal(String context, PufType pufType) {
        log.error("Operation not supported by this device.");
        return ERROR.getCode();
    }

    public VerifierExchangeResponseDTO getAttestationInternal(String refMeasurementHex, String appraisalPolicy) {
        log.error("Operation not supported by this device.");
        return new VerifierExchangeResponseDTO(ERROR.getCode(), "");
    }

    public int healthCheckInternal(TransportLayer transportLayer) {
        log.error("Operation not supported by this device.");
        return ERROR.getCode();
    }

    protected static void logAttestationResult(VerifierExchangeResponseDTO attestationResult) {
        switch (VerifierExchangeResponse.from(attestationResult.getStatus())) {
            case OK -> log.info("*** ATTESTATION PASSED ***");
            case FAIL -> log.error("*** ATTESTATION FAILED ***");
            case ERROR -> log.error("*** ATTESTATION ERROR ***");
        }
    }
}



