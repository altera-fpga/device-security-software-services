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

package com.intel.bkp.bkps.rest.prefetching.service;

import com.intel.bkp.bkps.attestation.mapping.CacheBytesMapper;
import com.intel.bkp.bkps.domain.PrefetchEntity;
import com.intel.bkp.bkps.repository.PrefetchRepository;
import com.intel.bkp.bkps.rest.onboarding.model.DeviceId;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;

import static com.intel.bkp.bkps.domain.enumeration.PrefetchEntityType.CERT;
import static com.intel.bkp.bkps.domain.enumeration.PrefetchEntityType.ZIP;

@Slf4j
@Service
public class ZipPrefetchRepositoryService extends PrefetchRepositoryServiceBase<byte[]> {

    public ZipPrefetchRepositoryService(PrefetchRepository prefetchRepository) {
        super(ZIP, prefetchRepository, new CacheBytesMapper());
    }

    public boolean isZipPrefetched(DeviceId deviceId) {
        final String pathPattern = getZipPattern(deviceId);
        log.debug("Checking existence of ZIP in DB using path: {}", pathPattern);
        return getPrefetchRepository()
            .existsByPathContainingIgnoreCaseAndType(pathPattern, getType());
    }

    public boolean isS10Prefetched(DeviceId deviceId) {
        log.debug("Checking existence of S10 certificate in DB: {}", deviceId);
        return getPrefetchRepository()
            .existsByPathContainingIgnoreCaseAndType(getS10CertPattern(deviceId), CERT);
    }

    public Optional<byte[]> find(DeviceId deviceId) {
        final String pathPattern = getZipPattern(deviceId);
        log.debug("Looking for ZIP in DB using path: {}", pathPattern);
        return getPrefetchRepository()
            .findByPathContainingIgnoreCaseAndType(pathPattern, getType())
            .map(PrefetchEntity::getContent)
            .map(getMapper()::decode);
    }

    private static String getZipPattern(DeviceId deviceId) {
        return "%s_%s".formatted(deviceId.getFamily().getAsHex(), deviceId.getDpUid());
    }

    private static String getS10CertPattern(DeviceId deviceId) {
        return "attestation_%s".formatted(deviceId.getDpUid());
    }
}
