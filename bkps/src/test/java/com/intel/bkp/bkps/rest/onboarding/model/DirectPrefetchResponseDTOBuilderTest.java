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

package com.intel.bkp.bkps.rest.onboarding.model;

import com.intel.bkp.bkps.programmer.model.CommunicationStatus;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DirectPrefetchResponseDTOBuilderTest {

    @Test
    void build_WithProgrammerCommands_ReturnNotEmpty() {
        // given
        DirectPrefetchResponseDTOBuilder sut = prepareBuilder(true);

        // when
        DirectPrefetchResponseDTO result = sut.build();

        // then
        assertEquals(CommunicationStatus.CONTINUE.getStatus(), result.getStatus());
        assertFalse(result.getJtagCommands().isEmpty());
    }

    @Test
    void build_WithNoProgrammerCommands_ReturnEmpty() {
        // given
        DirectPrefetchResponseDTOBuilder sut = prepareBuilder(false);

        // when
        final DirectPrefetchResponseDTO result = sut.build();

        // then
        assertEquals(CommunicationStatus.CONTINUE.getStatus(), result.getStatus());
        assertTrue(result.getJtagCommands().isEmpty());
    }

    @Test
    void done_WithProgrammerCommands_ReturnNotEmpty() {
        // given
        DirectPrefetchResponseDTOBuilder sut = prepareBuilder(true);

        // when
        DirectPrefetchResponseDTO result = sut.done();

        // then
        assertEquals(CommunicationStatus.DONE.getStatus(), result.getStatus());
        assertFalse(result.getJtagCommands().isEmpty());
    }

    @Test
    void done_WithNoProgrammerCommands_ReturnEmpty() {
        // given
        DirectPrefetchResponseDTOBuilder sut = prepareBuilder(false);

        // when
        DirectPrefetchResponseDTO result = sut.done();

        // then
        assertEquals(CommunicationStatus.DONE.getStatus(), result.getStatus());
        assertTrue(result.getJtagCommands().isEmpty());
    }

    private DirectPrefetchResponseDTOBuilder prepareBuilder(boolean notEmpty) {
        final ArrayList<ProgrammerMessage> commands = new ArrayList<>();
        if (notEmpty) {
            commands.add(new ProgrammerMessage(1, "test".getBytes()));
        }
        return new DirectPrefetchResponseDTOBuilder()
            .withMessages(commands);
    }
}
