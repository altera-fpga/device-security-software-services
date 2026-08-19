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

package com.intel.bkp.bkps.attestation;

import com.intel.bkp.bkps.exception.AppraisalPolicyNotFound;
import com.intel.bkp.bkps.repository.AppraisalPolicyRepository;
import com.intel.bkp.bkps.rest.configuration.service.AppraisalPolicyService;
import com.intel.bkp.fpgacerts.exceptions.SpdmAttestationException;
import com.intel.bkp.fpgacerts.spdm.SpdmAttestationResult;
import com.intel.bkp.protocol.spdm.jna.model.SpdmProtocol;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.function.Supplier;

import static com.intel.bkp.fpgacerts.verification.VerificationResult.PASSED;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static io.micrometer.common.util.StringUtils.isBlank;

@Service
@RequiredArgsConstructor
public class SpdmDiceAttestationService {

    private final SpdmDiceAttestationComponentFactory componentFactory;
    private final RimFetcher rimFetcher;
    private final AppraisalPolicyRepository appraisalPolicyRepository;
    private final AppraisalPolicyService appraisalPolicyService;

    public Integer performAttestationAndGetSlotId(SpdmProtocol spdmProtocol, String uid, AttestationParams params) {
        final SpdmAttestationResult result = performAttestation(spdmProtocol, uid, params);

        if (PASSED != result.verificationResult()) {
            throw new SpdmAttestationException("Attestation result: " + result.verificationResult());
        }

        return result.slotId();
    }

    private SpdmAttestationResult performAttestation(SpdmProtocol spdmProtocol, String uid, AttestationParams params) {
        final var attestationComponent = componentFactory.get(spdmProtocol, params);
        // Get Appraisal policy
        String policyContent = "";
        if (params.appraisalPolicyId() != 0) {
            // Get appraisal policy from database
            if (appraisalPolicyRepository.existsById(params.appraisalPolicyId())) {
                policyContent = appraisalPolicyService.findOneForDetails(params.appraisalPolicyId())
                    .orElseThrow(AppraisalPolicyNotFound::new);
            } else {
                throw new AppraisalPolicyNotFound();
            }
        }
        return attestationComponent.perform(getRimSupplier(params.corimUrl(), params.autoFetchFirmwareCorim()),
                                            policyContent,
                                            fromHex(uid));
    }

    private Supplier<String> getRimSupplier(String rimUrl, boolean autoFetchFirmwareCorim) {
        if (isBlank(rimUrl)) {
            if (autoFetchFirmwareCorim) {
                return null;
            } else {
                throw new SpdmAttestationException("Missing RIM URL - required for attestation");
            }
        }

        return () ->
            rimFetcher.fetchAsHex(rimUrl)
                .orElseThrow(() -> new SpdmAttestationException("Failed to fetch RIM: " + rimUrl));
    }
}
