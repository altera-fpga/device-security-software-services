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

import com.intel.bkp.bkps.config.ApplicationProperties;
import com.intel.bkp.bkps.exception.DeviceChainVerificationFailedException;
import com.intel.bkp.fpgacerts.dice.iidutils.IidFlowDetector;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static com.intel.bkp.utils.HexConverter.fromHex;

@Service
@Slf4j
@RequiredArgsConstructor
public class CertificateChainVerifier {

    private final ApplicationProperties applicationProperties;
    private final IidFlowDetector iidFlowDetector;

    public void verifyDiceChain(String deviceId, CertificateChainDTO chain,
                                boolean requireIidUds, boolean testModeSecrets) {
        log.info("Verifying DICE certificates chain...");
        final var diceVerifier =
            createDiceBkpChainVerifier(chain.getCachedCrls(), getTrustedRootHash(), testModeSecrets)
                .withDeviceId(fromHex(deviceId));

        verifyDiceChain("EFUSE UDS", chain.getCertificates(), diceVerifier::verifyChain);

        if (isIidChainRequired(requireIidUds, chain)) {
            verifyDiceChain("IID UDS", chain.getCertificatesIID(), diceVerifier::verifyChain);
        }

        log.info("Chain validation passed.");
    }

    private void verifyDiceChain(String chainType, LinkedList<X509Certificate> chain,
                                 Consumer<List<X509Certificate>> verifyChainCallback) {
        if (chain.isEmpty()) {
            throw new DeviceChainVerificationFailedException(
                "Required %s chain does not exist and cannot be verified".formatted(chainType));
        }

        log.debug("Verifying {} chain that has {} certificates.", chainType, chain.size());
        verifyChainCallback.accept(chain);
    }

    public void verifyS10Chain(String deviceId, CertificateChainDTO chain) {
        log.info("Verifying S10 certificates chain...");
        final var s10BkpChainVerifier = createS10BkpChainVerifier(chain.getCachedCrls(),
            getTrustedRootHash()).withDeviceId(fromHex(deviceId));

        s10BkpChainVerifier.verifyChain(chain.getCertificates());

        log.info("Chain validation passed.");
    }

    DiceBkpChainVerifier createDiceBkpChainVerifier(Map<String, X509CRL> cachedCrls, String[] rootHash,
                                                    boolean testModeSecrets) {
        return new DiceBkpChainVerifier(cachedCrls, rootHash, testModeSecrets);
    }

    S10BkpChainVerifier createS10BkpChainVerifier(Map<String, X509CRL> cachedCrls, String[] rootHash) {
        return new S10BkpChainVerifier(cachedCrls, rootHash);
    }

    private boolean isIidChainRequired(boolean requireIidUds, CertificateChainDTO chain) {
        return iidFlowDetector.withRequireIidUds(requireIidUds).isIidFlow(chain.getCertificates().getFirst());
    }

    private String[] getTrustedRootHash() {
        return applicationProperties.getDistributionPoint().getTrustedRootHash();
    }
}
