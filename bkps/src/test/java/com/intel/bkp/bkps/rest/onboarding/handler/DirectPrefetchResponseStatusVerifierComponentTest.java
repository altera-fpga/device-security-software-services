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

import com.intel.bkp.bkps.exception.PrefetchingGenericException;
import com.intel.bkp.bkps.programmer.model.ResponseStatus;
import com.intel.bkp.bkps.programmer.model.dto.ResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.DirectPrefetchRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.DirectPrefetchTransferObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DirectPrefetchResponseStatusVerifierComponentTest {

    private static final String REAL_RESPONSE_FROM_QUARTUS = "AAUAEA==";

    @Mock
    private DirectPrefetchHandler successor;

    @Mock
    private DirectPrefetchRequestDTO prefetchRequestDTO;

    @InjectMocks
    private DirectPrefetchQuartusStatusVerifierComponent sut;

    @BeforeEach
    void setUp() {
        sut.setSuccessor(successor);
    }

    @Test
    void handle_WithSucceededQuartusResponses_CallsSuccessor() {
        // given
        final DirectPrefetchTransferObject transferObject = prepareInitialConditions(true);

        // when
        sut.handle(transferObject);

        // then
        verify(successor).handle(transferObject);
    }

    @Test
    void handle_WithFailedQuartusResponses_ThrowsException() {
        // given
        final DirectPrefetchTransferObject transferObject = prepareInitialConditions(false);

        // when-then
        assertThrows(PrefetchingGenericException.class, () -> sut.handle(transferObject));
    }

    private DirectPrefetchTransferObject prepareInitialConditions(boolean isSuccess) {
        DirectPrefetchTransferObject transferObject = new DirectPrefetchTransferObject();
        transferObject.setDto(prefetchRequestDTO);

        final List<ResponseDTO> responses = new ArrayList<>();
        responses.add(new ResponseDTO(REAL_RESPONSE_FROM_QUARTUS,
            isSuccess ? ResponseStatus.ST_OK : ResponseStatus.ST_GENERIC_ERROR));
        when(prefetchRequestDTO.getJtagResponses()).thenReturn(responses);

        return transferObject;
    }
}
