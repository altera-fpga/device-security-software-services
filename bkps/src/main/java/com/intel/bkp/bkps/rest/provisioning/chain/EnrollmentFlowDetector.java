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

package com.intel.bkp.bkps.rest.provisioning.chain;

import com.intel.bkp.bkps.rest.prefetching.model.PrefetchChainDataDTO;
import com.intel.bkp.fpgacerts.dice.IEnrollmentFlowDetector;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.Arrays;

import static com.intel.bkp.crypto.x509.utils.KeyIdentifierUtils.getAuthorityKeyIdentifier;
import static com.intel.bkp.crypto.x509.utils.KeyIdentifierUtils.getSubjectKeyIdentifier;
import static com.intel.bkp.fpgacerts.chain.DistributionPointCertificate.getX509Certificates;
import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class EnrollmentFlowDetector implements IEnrollmentFlowDetector {

    private final X509Certificate firmwareCert;
    private final PrefetchChainDataDTO fetchedChain;

    public static EnrollmentFlowDetector instance(X509Certificate firmwareCert, PrefetchChainDataDTO fetchedChain) {
        return new EnrollmentFlowDetector(firmwareCert, fetchedChain);
    }

    @Override
    public boolean isEnrollmentFlow() {
        log.debug("Verifying if enrollment flow.");

        final var efuseChainFromDp = fetchedChain.getCertificates();
        if (efuseChainFromDp.isEmpty()) {
            log.debug("EFUSE UDS chain was not fetched.");
            return false;
        }
        final X509Certificate firstCertFromDp = getX509Certificates(efuseChainFromDp).iterator().next();
        final byte[] firstCertFromDpSki = getSubjectKeyIdentifier(firstCertFromDp);

        final byte[] firmwareAki = getAuthorityKeyIdentifier(firmwareCert);

        log.debug(String.format("Comparing firmware certificate AKI with SKI of first certificate downloaded from "
                + "distribution point (%s), if they match, it's not enrollment flow. %nAKI: %s%nSKI:%s",
            firstCertFromDp.getSubjectX500Principal(), toHex(firmwareAki), toHex(firstCertFromDpSki)));

        return !Arrays.equals(firmwareAki, firstCertFromDpSki);
    }
}
