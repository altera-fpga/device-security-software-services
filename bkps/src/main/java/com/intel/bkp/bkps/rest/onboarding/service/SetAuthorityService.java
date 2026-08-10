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

import com.intel.bkp.bkps.rest.onboarding.handler.SetAuthorityAdapterComponent;
import com.intel.bkp.bkps.rest.onboarding.handler.SetAuthorityCreateComponent;
import com.intel.bkp.bkps.rest.onboarding.handler.SetAuthorityDoneComponent;
import com.intel.bkp.bkps.rest.onboarding.handler.SetAuthorityHandler;
import com.intel.bkp.bkps.rest.onboarding.handler.SetAuthorityProtocolCommunicationComponent;
import com.intel.bkp.bkps.rest.onboarding.handler.SetAuthorityProtocolComponent;
import com.intel.bkp.bkps.rest.onboarding.handler.SetAuthorityProtocolDecisionCommunicationComponent;
import com.intel.bkp.bkps.rest.onboarding.handler.SetAuthorityProtocolDecisionComponent;
import com.intel.bkp.bkps.rest.onboarding.handler.SetAuthorityQuartusStatusVerifierComponent;
import com.intel.bkp.bkps.rest.onboarding.handler.SetAuthoritySupportedCommandsComponent;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityTransferObject;
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
public class SetAuthorityService {

    private final SetAuthoritySupportedCommandsComponent supportedCommandsComponent;
    private final SetAuthorityProtocolDecisionComponent protocolDecisionComponent;
    private final SetAuthorityAdapterComponent adapterComponent;
    private final SetAuthorityQuartusStatusVerifierComponent quartusStatusVerifierComponent;
    private final SetAuthorityProtocolDecisionCommunicationComponent protocolDecisionCommunicationComponent;
    private final SetAuthorityCreateComponent createComponent;
    private final SetAuthorityProtocolComponent protocolInitiateComponent;
    private final SetAuthorityProtocolCommunicationComponent protocolCommunicationComponent;
    private final SetAuthorityDoneComponent doneComponent;

    @Setter(value = PACKAGE)
    private SetAuthorityHandler entrypointComponent = new SetAuthorityHandler() {
    };

    @PostConstruct
    void init() {
        entrypointComponent.setSuccessor(supportedCommandsComponent);
        supportedCommandsComponent.setSuccessor(protocolDecisionComponent);
        protocolDecisionComponent.setSuccessor(adapterComponent);
        adapterComponent.setSuccessor(quartusStatusVerifierComponent);
        quartusStatusVerifierComponent.setSuccessor(protocolDecisionCommunicationComponent);
        protocolDecisionCommunicationComponent.setSuccessor(createComponent);
        createComponent.setSuccessor(protocolInitiateComponent);
        protocolInitiateComponent.setSuccessor(protocolCommunicationComponent);
        protocolCommunicationComponent.setSuccessor(doneComponent);
    }

    public SetAuthorityResponseDTO perform(SetAuthorityRequestDTO dto) {
        final SetAuthorityResponseDTO response = performInternal(dto);
        response.setApiVersion(dto.getApiVersion());
        return response;
    }

    private SetAuthorityResponseDTO performInternal(SetAuthorityRequestDTO dto) {
        return entrypointComponent.handle(
            SetAuthorityTransferObject.builder().dto(dto).build()
        );
    }
}
