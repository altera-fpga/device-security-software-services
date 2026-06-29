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

import com.intel.bkp.bkps.programmer.model.MessageType;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.programmer.model.ResponseStatus;
import com.intel.bkp.bkps.programmer.model.dto.ResponseDTO;
import com.intel.bkp.bkps.protocol.common.service.GetAttestationCertificateMessageSender;
import com.intel.bkp.bkps.protocol.common.service.GetChipIdMessageSender;
import com.intel.bkp.bkps.protocol.common.service.GetDeviceIdentityMessageSender;
import com.intel.bkp.bkps.protocol.common.service.GetIdCodeMessageSender;
import com.intel.bkp.bkps.rest.onboarding.model.DirectPrefetchRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.DirectPrefetchResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.DirectPrefetchTransferObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DirectPrefetchCreateComponentTest {

    private static final ProgrammerMessage PROGRAMMER_MESSAGE =
        ProgrammerMessage.from(MessageType.SEND_PACKET, new byte[]{1, 2});
    @Mock
    private DirectPrefetchTransferObject transferObject;

    @Mock
    private GetChipIdMessageSender getChipIdMessageSender;
    @Mock
    private GetIdCodeMessageSender getIdCodeMessageSender;
    @Mock
    private GetDeviceIdentityMessageSender getDeviceIdentityMessageSender;
    @Mock
    private GetAttestationCertificateMessageSender getAttestationCertificateMessageSender;

    @Mock
    private DirectPrefetchHandler successor;

    @Mock
    private DirectPrefetchRequestDTO prefetchRequestDTO;

    @InjectMocks
    private DirectPrefetchCreateComponent sut;

    @BeforeEach
    void setUp() {
        sut.setSuccessor(successor);
    }

    @Test
    void handle_WithNotEmptyResponses_CallsSuccessor() {
        // given
        prepareInitialConditions(false);

        // when
        sut.handle(transferObject);

        // then
        verify(successor).handle(transferObject);
    }

    @Test
    void handle_WithEmptyResponses_CallsPerform() {
        // given
        prepareInitialConditions(true);
        when(getChipIdMessageSender.create()).thenReturn(PROGRAMMER_MESSAGE);
        when(getIdCodeMessageSender.create()).thenReturn(PROGRAMMER_MESSAGE);
        when(getDeviceIdentityMessageSender.create()).thenReturn(PROGRAMMER_MESSAGE);
        when(getAttestationCertificateMessageSender.create()).thenReturn(PROGRAMMER_MESSAGE);

        // when
        final DirectPrefetchResponseDTO response = sut.handle(transferObject);

        // then
        verifyNoInteractions(successor);
        assertEquals(4, response.getJtagCommands().size());
    }

    private void prepareInitialConditions(boolean withEmptyResponses) {
        when(transferObject.getDto()).thenReturn(prefetchRequestDTO);
        final ArrayList<ResponseDTO> responses = new ArrayList<>();
        if (!withEmptyResponses) {
            responses.add(new ResponseDTO("test", ResponseStatus.ST_OK));
        }
        when(prefetchRequestDTO.getJtagResponses()).thenReturn(responses);
    }
}
