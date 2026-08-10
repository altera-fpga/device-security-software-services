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
import com.intel.bkp.bkps.exception.PrefetchingFailedToDownloadException;
import com.intel.bkp.bkps.rest.prefetching.model.PrefetchChainDataDTO;
import com.intel.bkp.core.properties.DistributionPoint;
import com.intel.bkp.fpgacerts.chain.DistributionPointCertificate;
import com.intel.bkp.fpgacerts.chain.DistributionPointCrl;
import com.intel.bkp.fpgacerts.dice.IpcsCertificateFetcher;
import com.intel.bkp.fpgacerts.dice.iidutils.IidFlowDetector;
import com.intel.bkp.utils.PathUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

@Service
@Slf4j
public class DiceDpFetchService extends FetchServiceBase<X509Certificate, PrefetchChainDataDTO> {

    private final IpcsCertificateFetcher ipcsCertificateFetcher;
    private final IidFlowDetector iidFlowDetector;

    protected DiceDpFetchService(ApplicationProperties applicationProperties,
                                 CacheChainFetcher chainFetcher,
                                 CacheCertificateFetcher certFetcher,
                                 CacheCrlMapFetcher crlFetcher,
                                 IidFlowDetector iidFlowDetector) {
        super(applicationProperties.getDistributionPoint(), chainFetcher, crlFetcher);

        final DistributionPoint dp = applicationProperties.getDistributionPoint();
        this.ipcsCertificateFetcher = new IpcsCertificateFetcher(certFetcher,
            PathUtils.buildPath(dp.getMainPath(), dp.getAttestationCertBasePath()));
        this.iidFlowDetector = iidFlowDetector;
    }

    @Override
    public PrefetchChainDataDTO fetch(X509Certificate enrollmentDeviceIdCert) {
        ipcsCertificateFetcher.clear();
        ipcsCertificateFetcher.setDeviceIdL0Cert(enrollmentDeviceIdCert);
        final var efuseChain = fetchEfuseUdsChain();
        final var iidChain = fetchIidUdsChain(enrollmentDeviceIdCert);
        final var notEmptyChain = ensureAtLeastOneChainFetched(efuseChain, iidChain);
        final var crls = fetchCrls(notEmptyChain);
        return new PrefetchChainDataDTO(efuseChain, iidChain, crls);
    }

    private List<DistributionPointCertificate> fetchEfuseUdsChain() {
        return fetchChain("EFUSE UDS", fetchDeviceIdCert().or(this::fetchEnrollmentCert));
    }

    private Optional<DistributionPointCertificate> fetchDeviceIdCert() {
        return ipcsCertificateFetcher.fetchIpcsDeviceIdCert();
    }

    private Optional<DistributionPointCertificate> fetchEnrollmentCert() {
        return ipcsCertificateFetcher.fetchIpcsEnrollmentCert();
    }

    private List<DistributionPointCertificate> fetchIidUdsChain(X509Certificate enrollmentDeviceIdCert) {
        return iidFlowDetector.isIidFlow(enrollmentDeviceIdCert)
               ? fetchChain("IID UDS", fetchIidUdsCert())
               : List.of();
    }

    private Optional<DistributionPointCertificate> fetchIidUdsCert() {
        return ipcsCertificateFetcher.fetchIpcsIidUdsCert();
    }

    private List<DistributionPointCertificate> fetchChain(String chainType,
                                                          Optional<DistributionPointCertificate> firstCertOfChain) {
        return firstCertOfChain
            .map(this::fetchChain)
            .orElseGet(() -> {
                log.warn("Failed to download first certificate of {} chain.", chainType);
                return List.of();
            });
    }

    private List<DistributionPointCertificate> fetchChain(DistributionPointCertificate firstCertOfChain) {
        final var certs = new LinkedList<DistributionPointCertificate>();
        certs.add(firstCertOfChain);
        certs.addAll(fetchCertificateChain(firstCertOfChain.getX509Cert()));
        return certs;
    }

    private List<DistributionPointCertificate> ensureAtLeastOneChainFetched(
        List<DistributionPointCertificate> certificates,
        List<DistributionPointCertificate> certificatesIid) {
        if (certificates.isEmpty() && certificatesIid.isEmpty()) {
            throw new PrefetchingFailedToDownloadException(
                "Failed to download at least one full chain (EFUSE or IID UDS).");
        }
        return certificates.isEmpty() ? certificatesIid : certificates;
    }

    @Override
    List<DistributionPointCrl> fetchCrls(List<DistributionPointCertificate> certificateChain) {
        final var crls = super.fetchCrls(certificateChain);
        if (!crls.isEmpty()) {
            final String crlUrlOriginal = crls.iterator().next().getUrl();
            final String crlUrl = crlUrlOriginal.replace(".crl", "_L1.crl");
            crls.add(getCrlFetcher().getCrl(crlUrl));
        }
        return crls;
    }
}
