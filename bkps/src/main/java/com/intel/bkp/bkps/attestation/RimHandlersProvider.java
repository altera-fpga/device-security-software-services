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

import com.intel.bkp.fpgacerts.cbor.service.CoRimHandler;
import com.intel.bkp.fpgacerts.dp.IDistributionPointConnector;
import com.intel.bkp.fpgacerts.rim.IRimHandler;
import com.intel.bkp.fpgacerts.rim.IRimHandlersProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RimHandlersProvider implements IRimHandlersProvider {

    private final IDistributionPointConnector dpConnector;
    private final String[] trustedRootHashes;
    private final boolean acceptUnsignedCorim;

    public RimHandlersProvider(@Value("${application.distribution-point.trusted-root-hash}") String[] trustedRootHashes,
                               @Value("${application.accept-unsigned-corim}") boolean acceptUnsignedCorim,
                               IDistributionPointConnector dpConnector) {
        this.dpConnector = dpConnector;
        this.trustedRootHashes = trustedRootHashes;
        this.acceptUnsignedCorim = acceptUnsignedCorim;
    }

    @Override
    public List<IRimHandler<?>> getRimHandlers() {
        return List.of(
            new CoRimHandler(dpConnector, trustedRootHashes, acceptUnsignedCorim)
        );
    }
}
