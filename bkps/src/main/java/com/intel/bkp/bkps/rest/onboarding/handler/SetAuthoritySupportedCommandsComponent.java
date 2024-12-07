/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2024 Intel Corporation. All Rights Reserved.
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

import com.intel.bkp.bkps.exception.CommandNotSupportedException;
import com.intel.bkp.bkps.programmer.model.MessageType;
import com.intel.bkp.bkps.programmer.sigma.SupportedMessageTypesFactory;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityTransferObject;
import com.intel.bkp.core.manufacturing.model.PufType;
import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class SetAuthoritySupportedCommandsComponent extends SetAuthorityHandler {

    @Override
    public SetAuthorityResponseDTO handle(SetAuthorityTransferObject transferObject) {
        final SetAuthorityRequestDTO dto = transferObject.getDto();
        log.debug(prepareLogEntry("verifying supported commands."));
        if (!isSupported(dto.getPufType(), dto.getSupportedCommands())) {
            throw new CommandNotSupportedException();
        }
        return successor.handle(transferObject);
    }

    private boolean isSupported(@NotNull Integer pufTypeValue, int supportedCommands) {
        if (noCommandIsSupported(supportedCommands)) {
            return false;
        }

        final PufType pufType = PufType.fromOrdinal(pufTypeValue);

        return MessageType.areSetIn(SupportedMessageTypesFactory.getRequired(), supportedCommands)
            && SupportedMessageTypesFactory.getForSetAuthority(pufType).isSetIn(supportedCommands);
    }

    private boolean noCommandIsSupported(int supportedCommands) {
        return 0 == supportedCommands;
    }
}
