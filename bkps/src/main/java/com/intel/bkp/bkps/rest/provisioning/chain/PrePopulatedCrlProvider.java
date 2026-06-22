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

package com.intel.bkp.bkps.rest.provisioning.chain;

import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.fpgacerts.interfaces.ICrlProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.Path;
import java.security.cert.X509CRL;
import java.util.Map;

@RequiredArgsConstructor
@Slf4j
public class PrePopulatedCrlProvider implements ICrlProvider {

    private final Map<String, X509CRL> cachedCrls;

    @Override
    public X509CRL getCrl(String crlUrl) {
        if (!cachedCrls.containsKey(crlUrl)) {
            crlUrl = getCachedUrlForCrlWithTheSameFilename(crlUrl);
        }

        final X509CRL cachedCrl = cachedCrls.get(crlUrl);
        log.debug("Using cached CRL: {}", crlUrl);
        return cachedCrl;
    }

    /**
     * Looks for cached URL that ends with the same filename as requested original URL. If such URL exists returns
     * cached CRL associated with it, if not, throws BKPRuntimeException.
     * <br>
     * <br>This method enables to use different distribution point than intel production (tsci.intel.com),
     * because certificates issued by FPGA device contain hardcoded URLs to L0 and L1 CRLs on intel production DP.
     * <br>
     * <br> For example firmware certificate from Agilex device contains following URL to L1 CRL:
     * <br>- <a href="https://tsci.intel.com/content/IPCS/crls/IPCS_agilex_L1.crl">...</a>
     * <br>
     * <br>If BKPS is configured to use custom DP, L1 CRL must also be from this custom DP,
     * otherwise it would be impossible to verify that CRL was signed by trusted issuer.
     * <br>
     * <br>Assumption is that if customer wants to use custom DP, it must contain L0 and L1 CRLs with
     * following filenames:
     * <br> - for L0: IPCS_{@literal <familyNameInLowercase>}.crl
     * <br> - for L1: IPCS_{@literal <familyNameInLowercase>}_L1.crl
     */
    private String getCachedUrlForCrlWithTheSameFilename(String originalCrlUrl) {
        log.debug("Looking for cached URL to CRL with the same filename: {}", originalCrlUrl);
        String crlFilename = Path.of(originalCrlUrl).getFileName().toString();

        return cachedCrls.keySet().stream()
            .filter(url -> url.endsWith(crlFilename))
            .findFirst()
            .orElseThrow(() -> new ProvisioningGenericException(ErrorCodeMap.CRL_NOT_FOUND));
    }
}
