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

package com.intel.bkp.bkps.rest.onboarding.model;

import com.intel.bkp.bkps.programmer.model.ResponseStatus;
import com.intel.bkp.bkps.programmer.model.dto.ResponseDTO;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DirectPrefetchRequestDTOReaderTest {

    private static final String REAL_RESPONSE_FROM_QUARTUS = "AAUAEA==";

    @Mock
    private DirectPrefetchRequestDTO dto;

    @Test
    void constructor_WithValidPayload_Success() {
        // given
        final ArrayList<ResponseDTO> responses = new ArrayList<>();
        responses.add(new ResponseDTO(REAL_RESPONSE_FROM_QUARTUS, ResponseStatus.ST_OK));
        when(dto.getJtagResponses()).thenReturn(responses);

        // when
        final DirectPrefetchRequestDTOReader instance = new DirectPrefetchRequestDTOReader(dto);

        // then
        assertEquals(dto, instance.getDto());
        assertEquals(1, instance.getJtagResponses().size());
    }
}
