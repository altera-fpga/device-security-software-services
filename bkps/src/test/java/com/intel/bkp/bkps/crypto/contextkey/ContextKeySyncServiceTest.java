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

package com.intel.bkp.bkps.crypto.contextkey;

import com.intel.bkp.bkps.domain.ContextKey;
import com.intel.bkp.bkps.repository.ContextKeyRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class ContextKeySyncServiceTest {

    @Mock
    private ContextKeyRepository contextKeyRepository;

    @Mock
    private UnwrappedContextKey unwrappedContextKey;

    @Mock
    private ContextKey contextKey;

    @InjectMocks
    private ContextKeySyncService sut;

    @Test
    void inSync_GetKeyFromRepository() {
        // when
        sut.inSync(unwrappedContextKey);

        // then
        verify(contextKeyRepository).getActualContextKey();
    }

    @Test
    void inSync_KeyNotPresent_ReturnFalse() {
        // given
        mockKeyNotPresent();

        // when
        boolean result = sut.inSync(unwrappedContextKey);

        // then
        assertFalse(result);
    }

    @Test
    void inSync_KeysAreNotEqual_ReturnsFalse() {
        // given
        mockKeyPresent();
        when(unwrappedContextKey.getContextKey()).thenReturn(new ContextKey());

        // when
        boolean result = sut.inSync(unwrappedContextKey);

        // then
        assertFalse(result);
    }

    @Test
    void inSync_KeysAreEqual_ReturnsTrue() {
        // given
        mockKeyPresent();
        when(unwrappedContextKey.getContextKey()).thenReturn(contextKey);

        // when
        boolean result = sut.inSync(unwrappedContextKey);

        // then
        assertTrue(result);
    }

    private void mockKeyPresent() {
        when(contextKeyRepository.getActualContextKey()).thenReturn(Optional.of(contextKey));
    }

    private void mockKeyNotPresent() {
        when(contextKeyRepository.getActualContextKey()).thenReturn(Optional.empty());
    }

}
