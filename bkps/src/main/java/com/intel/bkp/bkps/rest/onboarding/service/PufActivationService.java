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

import com.intel.bkp.bkps.rest.onboarding.handler.PufActivateCreateComponent;
import com.intel.bkp.bkps.rest.onboarding.handler.PufActivateDoneComponent;
import com.intel.bkp.bkps.rest.onboarding.handler.PufActivateHandler;
import com.intel.bkp.bkps.rest.onboarding.handler.PufActivatePushDataComponent;
import com.intel.bkp.bkps.rest.onboarding.handler.PufActivateQuartusStatusVerifierComponent;
import com.intel.bkp.bkps.rest.onboarding.handler.PufActivateSupportedCommandsComponent;
import com.intel.bkp.bkps.rest.onboarding.model.PufActivateRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.PufActivateResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.PufActivateTransferObject;
import jakarta.annotation.PostConstruct;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import static lombok.AccessLevel.PACKAGE;

@Service
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class PufActivationService {

    private final PufActivateSupportedCommandsComponent supportedCommandsComponent;
    private final PufActivateCreateComponent createComponent;
    private final PufActivateQuartusStatusVerifierComponent quartusStatusVerifierComponent;
    private final PufActivatePushDataComponent pushDataComponent;
    private final PufActivateDoneComponent doneComponent;

    @Setter(value = PACKAGE)
    private PufActivateHandler entrypointComponent = new PufActivateHandler() {
    };

    @PostConstruct
    void init() {
        entrypointComponent.setSuccessor(supportedCommandsComponent);
        supportedCommandsComponent.setSuccessor(createComponent);
        createComponent.setSuccessor(quartusStatusVerifierComponent);
        quartusStatusVerifierComponent.setSuccessor(pushDataComponent);
        pushDataComponent.setSuccessor(doneComponent);
    }

    public PufActivateResponseDTO perform(PufActivateRequestDTO dto) {
        final PufActivateResponseDTO response = performInternal(dto);
        response.setApiVersion(dto.getApiVersion());
        return response;
    }

    private PufActivateResponseDTO performInternal(PufActivateRequestDTO dto) {
        return entrypointComponent.handle(
            PufActivateTransferObject.builder().dto(dto).build()
        );
    }
}
