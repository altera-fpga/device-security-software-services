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

package com.intel.bkp.bkps.rest.onboarding.event;

import com.intel.bkp.bkps.rest.onboarding.model.DeviceId;
import com.intel.bkp.bkps.rest.onboarding.service.ZipDataProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import static com.intel.bkp.bkps.domain.enumeration.FamilyExtended.FAMILIES_WITH_PREFETCH_SUPPORTED;
import static com.intel.bkp.bkps.domain.enumeration.PrefetchType.getPrefetchType;

@Slf4j
@Component
@RequiredArgsConstructor
public class PrefetchEventListener {

    private final ZipDataProvider zipDataProvider;
    private final PrefetchEventQueueService prefetchEventQueueService;

    @EventListener
    public void onApplicationEvent(@NonNull PrefetchEvent event) {
        log.info("Received prefetching event: {}", event);

        prefetchEventQueueService.add(event);

        final DeviceId deviceId = event.getDeviceId();
        try {
            switch (getPrefetchType(deviceId)) {
                case S10 -> zipDataProvider.fetchS10(deviceId.getDpUid());
                case ZIP_WITH_SKI, ZIP_WITH_PDI -> zipDataProvider.fetchDice(deviceId.getDpUid(),
                    deviceId.getFamily(), deviceId.getId());
                case NONE -> throw new IllegalArgumentException(
                    "Prefetching is only supported for platforms: " + FAMILIES_WITH_PREFETCH_SUPPORTED);
            }
        } finally {
            prefetchEventQueueService.remove(event);
        }
    }
}
