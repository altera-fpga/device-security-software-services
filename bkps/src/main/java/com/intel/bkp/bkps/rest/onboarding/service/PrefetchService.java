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

package com.intel.bkp.bkps.rest.onboarding.service;

import com.intel.bkp.bkps.exception.PrefetchingGenericException;
import com.intel.bkp.bkps.rest.onboarding.handler.PrefetchQueueProvider;
import com.intel.bkp.bkps.rest.onboarding.model.DeviceId;
import com.intel.bkp.crypto.exceptions.X509CertificateParsingException;
import com.intel.bkp.fpgacerts.model.Family;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.util.Optional;

import static com.intel.bkp.bkps.domain.enumeration.FamilyExtended.FAMILIES_WITH_PREFETCH_SUPPORTED;
import static com.intel.bkp.bkps.domain.enumeration.PrefetchType.getPrefetchType;
import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.toX509Certificate;

@Service
@Slf4j
@RequiredArgsConstructor
public class PrefetchService {

    private final PrefetchQueueProvider prefetchQueueProvider;

    public void enqueue(DeviceId deviceId, Optional<byte[]> deviceIdErCertBytes) {
        switch (getPrefetchType(deviceId)) {
            case S10, ZIP_WITH_PDI -> enqueuePrefetch(deviceId);
            case ZIP_WITH_SKI -> enqueuePrefetch(getDeviceIdWithKeyIdentifier(deviceId, deviceIdErCertBytes));
            case NONE -> throw new PrefetchingGenericException(
                "Prefetching is only supported for platforms: " + FAMILIES_WITH_PREFETCH_SUPPORTED);
        }
    }

    private void enqueuePrefetch(DeviceId deviceId) {
        log.debug("Enqueuing prefetch for {} board.", deviceId.getFamily().getFamilyName());
        prefetchQueueProvider.pushToQueue(deviceId);
    }

    private DeviceId getDeviceIdWithKeyIdentifier(DeviceId deviceId, Optional<byte[]> certBytes) {
        final X509Certificate cert = parseCertificate(certBytes, deviceId.getFamily());
        deviceId.setExplicitId(
            DeviceIdEnrollmentCertificate.from(cert).getKeyIdentifierBasedOnSvn()
        );
        return deviceId;
    }

    private X509Certificate parseCertificate(Optional<byte[]> certBytes, Family family) {
        return certBytes
            .filter(bytes -> bytes.length > 0)
            .map(this::parseCertificate)
            .orElseThrow(() ->
                new PrefetchingGenericException("Certificate required for given Family: " + family.getFamilyName())
            );
    }

    private X509Certificate parseCertificate(byte[] certBytes) {
        try {
            return toX509Certificate(certBytes);
        } catch (X509CertificateParsingException e) {
            throw new PrefetchingGenericException("Parsing certificate failed.", e);
        }
    }
}
