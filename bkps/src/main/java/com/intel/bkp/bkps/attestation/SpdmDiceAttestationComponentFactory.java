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

import com.intel.bkp.bkps.config.ApplicationProperties;
import com.intel.bkp.bkps.rest.provisioning.chain.CacheCrlProvider;
import com.intel.bkp.bkps.rest.provisioning.chain.DiceBkpChainVerifier;
import com.intel.bkp.fpgacerts.dice.iidutils.IidFlowDetector;
import com.intel.bkp.fpgacerts.dp.IDistributionPointConnector;
import com.intel.bkp.fpgacerts.rim.IRimHandlersProvider;
import com.intel.bkp.fpgacerts.rim.RimUrlProvider;
import com.intel.bkp.fpgacerts.spdm.SpdmDiceAttestationComponentBase;
import com.intel.bkp.fpgacerts.url.DistributionPointAddressProvider;
import com.intel.bkp.protocol.spdm.jna.model.SpdmProtocol;
import com.intel.bkp.utils.PathUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SpdmDiceAttestationComponentFactory {

    private final ApplicationProperties applicationProperties;
    private final IidFlowDetector iidFlowDetector;
    private final CacheCrlProvider crlProvider;
    private final IRimHandlersProvider rimHandlersProvider;
    private final IDistributionPointConnector dpConnector;

    public SpdmDiceAttestationComponentBase get(SpdmProtocol spdmProtocol, AttestationParams params) {
        final var trustedRootHashes = getTrustedRootHashes();
        final var diceChainVerifier =
            new DiceBkpChainVerifier(crlProvider, trustedRootHashes, params.testModeSecrets());
        final var chainSearcher = new SpdmChainSearcher(spdmProtocol,
            iidFlowDetector.withRequireIidUds(params.requireIidUds()),
            diceChainVerifier, trustedRootHashes
        );
        final var rimUrlProvider = new RimUrlProvider(new DistributionPointAddressProvider(getRimUrlPrefix()));
        final var newRimUrlProvider = new RimUrlProvider(new DistributionPointAddressProvider(getNewRimUrlPrefix()));
        return new SpdmDiceAttestationComponentImpl(spdmProtocol, chainSearcher, rimHandlersProvider, rimUrlProvider, newRimUrlProvider, dpConnector);
    }

    private String[] getTrustedRootHashes() {
        return applicationProperties.getDistributionPoint().getTrustedRootHash();
    }

    private String getRimUrlPrefix() {
        final var dp = applicationProperties.getDistributionPoint();
        return PathUtils.buildPath(dp.getMainPath(), dp.getRimDataBasePath());
    }

    private String getNewRimUrlPrefix() {
        final var dp = applicationProperties.getDistributionPoint();
        return PathUtils.buildPath(dp.getMainPath(), dp.getRimDataBasePathV2());
    }
}
