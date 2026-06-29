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

package com.intel.bkp.bkps.rest.onboarding.handler;

import com.intel.bkp.bkps.exception.PrefetchingStatusFailed;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.onboarding.event.PrefetchEventQueueService;
import com.intel.bkp.bkps.rest.onboarding.model.DeviceId;
import com.intel.bkp.bkps.rest.onboarding.model.PrefetchStatusRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.PrefetchStatusResponseDTO;
import com.intel.bkp.bkps.rest.prefetching.service.ZipPrefetchRepositoryService;
import com.intel.bkp.fpgacerts.model.Family;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import static org.apache.commons.lang3.StringUtils.isAllBlank;
import static org.apache.commons.lang3.StringUtils.isNoneBlank;

@Slf4j
@Service
@RequiredArgsConstructor
public class PrefetchStatusService {

    private final ZipPrefetchRepositoryService prefetchRepositoryService;
    private final PrefetchEventQueueService prefetchEventQueueService;

    public PrefetchStatusResponseDTO isPrefetched(PrefetchStatusRequestDTO dto) {
        final String familyId = dto.familyId();
        final String uid = dto.uid();

        if (isAllBlank(familyId, uid)) {
            if (prefetchEventQueueService.isEmpty()) {
                return PrefetchStatusResponseDTO.PREFETCH_DONE;
            }

            return PrefetchStatusResponseDTO.PREFETCH_IN_PROGRESS;
        }

        if (isNoneBlank(familyId, uid)) {
            final DeviceId deviceId = DeviceId.instance(getFamily(familyId), dto.uid());

            if (Family.S10 == deviceId.getFamily() && prefetchRepositoryService.isS10Prefetched(deviceId)) {
                return PrefetchStatusResponseDTO.PREFETCH_DONE;
            }

            if (prefetchRepositoryService.isZipPrefetched(deviceId)) {
                return PrefetchStatusResponseDTO.PREFETCH_DONE;
            }

            if (prefetchEventQueueService.isInProgress(deviceId)) {
                return PrefetchStatusResponseDTO.PREFETCH_IN_PROGRESS;
            }

            return PrefetchStatusResponseDTO.PREFETCH_NOT_FOUND;
        }

        throw new PrefetchingStatusFailed(ErrorCodeMap.PREFETCHING_STATUS_FAILED_INVALID_PARAMS);
    }

    private static Family getFamily(String familyId) {
        try {
            return Family.from(familyId);
        } catch (Exception e) {
            throw new PrefetchingStatusFailed(ErrorCodeMap.PREFETCHING_STATUS_FAILED_INVALID_FAMILY, e);
        }
    }
}
