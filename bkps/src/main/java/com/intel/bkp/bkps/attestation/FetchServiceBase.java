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

import com.intel.bkp.core.properties.DistributionPoint;
import com.intel.bkp.fpgacerts.chain.DistributionPointCertificate;
import com.intel.bkp.fpgacerts.chain.DistributionPointCrl;
import com.intel.bkp.fpgacerts.url.DistributionPointAddressProvider;
import com.intel.bkp.utils.PathUtils;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.List;

@Slf4j
@Getter(AccessLevel.PROTECTED)
public abstract class FetchServiceBase<T, S> {

    private final DistributionPointAddressProvider addressProvider;
    private final CacheChainFetcher chainFetcher;
    private final CacheCrlMapFetcher crlFetcher;

    FetchServiceBase(DistributionPoint dp,
                     CacheChainFetcher chainFetcher,
                     CacheCrlMapFetcher crlFetcher) {
        this.addressProvider = new DistributionPointAddressProvider(
            PathUtils.buildPath(dp.getMainPath(), dp.getAttestationCertBasePath()));
        this.chainFetcher = chainFetcher;
        this.crlFetcher = crlFetcher;
    }

    public abstract S fetch(T data);

    List<DistributionPointCertificate> fetchCertificateChain(String url) {
        return chainFetcher.fetchCertificateChain(url);
    }

    List<DistributionPointCertificate> fetchCertificateChain(X509Certificate cert) {
        return chainFetcher.fetchCertificateChain(cert);
    }

    List<DistributionPointCrl> fetchCrls(List<DistributionPointCertificate> certificateChain) {
        return crlFetcher.fetchCrls(certificateChain);
    }
}
