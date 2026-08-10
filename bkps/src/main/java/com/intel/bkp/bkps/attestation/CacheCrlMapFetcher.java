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

import com.intel.bkp.bkps.exception.PrefetchingGenericException;
import com.intel.bkp.crypto.x509.utils.CrlDistributionPointsUtils;
import com.intel.bkp.fpgacerts.chain.DistributionPointCertificate;
import com.intel.bkp.fpgacerts.chain.DistributionPointCrl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class CacheCrlMapFetcher {

    private final CacheCrlFetcher crlFetcher;

    public List<DistributionPointCrl> fetchCrls(List<DistributionPointCertificate> certificateChain) {
        return certificateChain
            .stream()
            .map(DistributionPointCertificate::getX509Cert)
            .map(CrlDistributionPointsUtils::getCrlUrl)
            .filter(Optional::isPresent)
            .map(Optional::get)
            .map(this::getCrl)
            .collect(Collectors.toList());
    }

    public DistributionPointCrl getCrl(String url) {
        return crlFetcher.fetch(url)
            .map(crl -> new DistributionPointCrl(url, crl))
            .orElseThrow(() -> getFetchingFailureException(url));
    }

    private RuntimeException getFetchingFailureException(String url) {
        return new PrefetchingGenericException("Failed to download CRL: " + url);
    }
}
