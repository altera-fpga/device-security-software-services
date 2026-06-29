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

import com.intel.bkp.bkps.rest.onboarding.handler.PrefetchStatusService;
import com.intel.bkp.bkps.rest.onboarding.model.DirectPrefetchRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.DirectPrefetchResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.PrefetchStatusRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.PrefetchStatusResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.PufActivateRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.PufActivateResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityResponseDTO;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class OnboardingService {

    private final DirectPrefetchService directPrefetchService;
    private final PrefetchStatusService prefetchStatusService;
    private final PufActivationService pufActivationService;
    private final SetAuthorityService setAuthorityService;

    public DirectPrefetchResponseDTO directPrefetch(DirectPrefetchRequestDTO dto) {
        return directPrefetchService.perform(dto);
    }

    public PrefetchStatusResponseDTO prefetchStatus(PrefetchStatusRequestDTO dto) {
        return prefetchStatusService.isPrefetched(dto);
    }

    public PufActivateResponseDTO pufActivate(PufActivateRequestDTO dto) {
        return pufActivationService.perform(dto);
    }

    public SetAuthorityResponseDTO setAuthority(SetAuthorityRequestDTO dto) {
        return setAuthorityService.perform(dto);
    }
}
