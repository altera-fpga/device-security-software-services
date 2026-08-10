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

import com.intel.bkp.bkps.domain.enumeration.PrefetchStatus;
import com.intel.bkp.bkps.rest.onboarding.model.DeviceId;
import com.intel.bkp.bkps.rest.onboarding.service.PrefetchService;
import com.intel.bkp.bkps.rest.prefetching.model.IndirectPrefetchRequestDTO;
import com.intel.bkp.bkps.rest.prefetching.model.PrefetchStatusDTO;
import com.intel.bkp.crypto.pem.PemFormatEncoder;
import com.intel.bkp.fpgacerts.model.Family;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.bkps.domain.enumeration.PrefetchStatus.ERROR;
import static com.intel.bkp.bkps.domain.enumeration.PrefetchStatus.PROGRESS;
import static lombok.AccessLevel.PACKAGE;

@Service
@RequiredArgsConstructor(access = PACKAGE)
@Slf4j
@Transactional(isolation = Isolation.SERIALIZABLE)
public class IndirectPrefetchService {

    private final PrefetchService prefetchService;

    public List<PrefetchStatusDTO> prefetchDevices(List<IndirectPrefetchRequestDTO> dtos) {
        return dtos
            .stream()
            .map(this::prefetchDevice)
            .toList();
    }

    private PrefetchStatusDTO prefetchDevice(IndirectPrefetchRequestDTO dto) {
        return new PrefetchStatusDTO(dto.getUid(), indirectPrefetch(dto));
    }

    private PrefetchStatus indirectPrefetch(IndirectPrefetchRequestDTO dto) {
        final DeviceId deviceId = getDeviceIdFromRequest(dto);
        final Optional<byte[]> cert = getCertAsByteArray(dto);

        try {
            prefetchService.enqueue(deviceId, cert);
            return PROGRESS;
        } catch (Exception e) {
            log.error("Failed to perform indirect prefetch for " + deviceId.getUid(), e);
            return ERROR;
        }
    }

    private DeviceId getDeviceIdFromRequest(IndirectPrefetchRequestDTO dto) {
        return DeviceId.instance(Family.from(dto.getFamilyId()), dto.getUid(), dto.getPdi());
    }

    Optional<byte[]> getCertAsByteArray(IndirectPrefetchRequestDTO dto) {
        return Optional.ofNullable(dto.getDeviceIdEr()).map(x -> tryToDecodeCert(dto));
    }

    private byte[] tryToDecodeCert(IndirectPrefetchRequestDTO dto) {
        try {
            return PemFormatEncoder.decode(dto.getDeviceIdEr());
        } catch (IOException | IllegalArgumentException e) {
            log.warn("Failed to parse PEM certificate for device with uid {} . Certificate set to null",
                dto.getUid());
            return null;
        }
    }
}
