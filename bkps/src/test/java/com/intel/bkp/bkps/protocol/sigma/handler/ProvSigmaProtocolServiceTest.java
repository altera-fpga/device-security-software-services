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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.mockito.Mockito.verify;


@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ProvSigmaProtocolServiceTest {

    @Mock
    private ProvSigmaCreateComponent provSigmaCreateComponent;

    @Mock
    private ProvInitComponent provInitComponent;

    @Mock
    private ProvAuthComponent provAuthComponent;

    @Mock
    private ProvVerifyM3Component provVerifyM3Component;

    @Mock
    private ProvVerifyEncComponent provVerifyEncComponent;

    @Mock
    private ProvEncClearBbramComponent provEncClearBbramComponent;

    @Mock
    private ProvEncAssetComponent provEncAssetComponent;

    @Mock
    private ProvProvisionComponent provProvisionComponent;

    @Mock
    private ProvDoneComponent provDoneComponent;

    @InjectMocks
    private ProvSigmaProtocolService sut;

    @Test
    void init_VerifySuccessors() {
        // when
        sut.init();

        // then
        verify(provSigmaCreateComponent).setSuccessor(provInitComponent);
        verify(provInitComponent).setSuccessor(provAuthComponent);
        verify(provAuthComponent).setSuccessor(provVerifyM3Component);
        verify(provVerifyM3Component).setSuccessor(provVerifyEncComponent);
        verify(provVerifyEncComponent).setSuccessor(provEncClearBbramComponent);
        verify(provEncClearBbramComponent).setSuccessor(provEncAssetComponent);
        verify(provEncAssetComponent).setSuccessor(provProvisionComponent);
        verify(provProvisionComponent).setSuccessor(provDoneComponent);
    }

}
