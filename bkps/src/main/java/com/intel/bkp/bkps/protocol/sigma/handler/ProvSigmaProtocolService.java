/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2025 Altera Corporation. All Rights Reserved.
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

package com.intel.bkp.bkps.protocol.sigma.handler;

import com.intel.bkp.bkps.protocol.common.handler.ProvDoneComponent;
import com.intel.bkp.bkps.protocol.common.model.SigmaProtocol;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import jakarta.annotation.PostConstruct;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
@ConditionalOnProperty(prefix = "service.protocol", name = "sigma")
public class ProvSigmaProtocolService implements SigmaProtocol {

    private final ProvSigmaCreateComponent provSigmaCreateComponent;
    private final ProvInitComponent provInitComponent;
    private final ProvAuthComponent provAuthComponent;
    private final ProvVerifyM3Component provVerifyM3Component;
    private final ProvVerifyEncComponent provVerifyEncComponent;
    private final ProvEncClearBbramComponent provEncClearBbramComponent;
    private final ProvEncAssetComponent provEncAssetComponent;
    private final ProvProvisionComponent provProvisionComponent;
    private final ProvDoneComponent provDoneComponent;

    @PostConstruct
    void init() {
        provSigmaCreateComponent.setSuccessor(provInitComponent);
        provInitComponent.setSuccessor(provAuthComponent);
        provAuthComponent.setSuccessor(provVerifyM3Component);
        provVerifyM3Component.setSuccessor(provVerifyEncComponent);
        provVerifyEncComponent.setSuccessor(provEncClearBbramComponent);
        provEncClearBbramComponent.setSuccessor(provEncAssetComponent);
        provEncAssetComponent.setSuccessor(provProvisionComponent);
        provProvisionComponent.setSuccessor(provDoneComponent);
    }

    @Override
    public ProvisioningResponseDTO run(ProvisioningTransferObject transferObject) {
        return provSigmaCreateComponent.handle(transferObject);
    }
}
