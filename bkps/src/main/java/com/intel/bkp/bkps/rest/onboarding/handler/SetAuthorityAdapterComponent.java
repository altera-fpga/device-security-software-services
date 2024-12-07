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

import com.intel.bkp.bkps.exception.SetAuthorityGenericException;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityRequestDTOReader;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityTransferObject;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@AllArgsConstructor
public class SetAuthorityAdapterComponent extends SetAuthorityHandler {

    private final SetAuthorityRequestDTOManager requestDTOManager;

    @Override
    public SetAuthorityResponseDTO handle(SetAuthorityTransferObject transferObject) {
        try {
            final SetAuthorityRequestDTOReader dtoReader = requestDTOManager
                .getReader(transferObject.getDto());
            transferObject.setDtoReader(dtoReader);
            return successor.handle(transferObject);
        } catch (EncryptionProviderException e) {
            throw new SetAuthorityGenericException(e);
        } catch (IOException e) {
            throw new SetAuthorityGenericException("Failed to deserialize context.", e);
        }
    }
}
