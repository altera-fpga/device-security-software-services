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
import com.intel.bkp.bkps.rest.prefetching.model.PrefetchChainDataDTO;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.fpgacerts.chain.DistributionPointCertificate;
import com.intel.bkp.fpgacerts.url.params.S10Params;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

import static com.intel.bkp.utils.HexConverter.fromHex;

@Service
@Slf4j
public class S10DpFetchService extends FetchServiceBase<String, PrefetchChainDataDTO> {

    private static final String PUF_TYPE_HEX = PufType.getPufTypeHex(PufType.EFUSE);

    public S10DpFetchService(ApplicationProperties applicationProperties,
                             CacheChainFetcher chainFetcher,
                             CacheCrlMapFetcher crlFetcher) {
        super(applicationProperties.getDistributionPoint(), chainFetcher, crlFetcher);
    }

    @Override
    public PrefetchChainDataDTO fetch(String deviceIdHex) {
        final var certificateMap = fetchCertificates(fromHex(deviceIdHex));
        final var crlMap = fetchCrls(certificateMap);
        return new PrefetchChainDataDTO(certificateMap, crlMap);
    }

    private List<DistributionPointCertificate> fetchCertificates(byte[] deviceId) {
        log.debug("Building PufAttestation certificate chain.");
        final String url = getAddressProvider().getAttestationCertUrl(S10Params.from(deviceId, PUF_TYPE_HEX));
        return fetchCertificateChain(url);
    }
}
