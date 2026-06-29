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

package com.intel.bkp.verifier.protocol.spdm.service;

import com.intel.bkp.fpgacerts.dp.DistributionPointCrlProvider;
import com.intel.bkp.fpgacerts.spdm.SpdmChainSearcherBase;
import com.intel.bkp.protocol.spdm.jna.model.SpdmProtocol;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.service.certificate.DiceAliasChainVerifier;
import com.intel.bkp.verifier.service.certificate.IidAliasFlowDetector;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SpdmChainSearcher extends SpdmChainSearcherBase {

    @Getter(value = AccessLevel.PROTECTED)
    private final String[] trustedRootHashes;

    public SpdmChainSearcher(SpdmProtocol spdmProtocol) {
        this(AppContext.instance(), spdmProtocol);
    }

    private SpdmChainSearcher(AppContext appContext, SpdmProtocol spdmProtocol) {
        super(spdmProtocol, new IidAliasFlowDetector(),
            new DiceAliasChainVerifier(
                new DistributionPointCrlProvider(appContext.getDpConnector()),
                appContext.getDpTrustedRootHashes(),
                appContext.getLibConfig().isTestModeSecrets()
            )
        );
        this.trustedRootHashes = appContext.getDpTrustedRootHashes();
    }
}
