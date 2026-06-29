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

package com.intel.bkp.bkps.crypto.sealingkey;

import com.intel.bkp.bkps.domain.SealingKeyBackupHash;
import com.intel.bkp.bkps.exception.SealingKeyBackupHashDoesNotExistException;
import com.intel.bkp.bkps.exception.SealingKeyBackupHashDoesNotMatchException;
import com.intel.bkp.bkps.repository.SealingKeyBackupHashRepository;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class SealingKeyBackupHashManagerTest {

    @Mock
    private SealingKeyBackupHashRepository sealingKeyBackupHashRepository;

    @InjectMocks
    private SealingKeyBackupHashManager sut;

    private static final byte[] VALID_DATA = new byte[10];
    private static final byte[] INVALID_DATA = new byte[30];
    private static final SealingKeyBackupHash validEntity = new SealingKeyBackupHash(DigestUtils.sha256Hex(VALID_DATA));

    @Test
    void update_Success() {
        // when
        sut.update(VALID_DATA);

        // then
        verify(sealingKeyBackupHashRepository).deleteAll();
        verify(sealingKeyBackupHashRepository).save(any(SealingKeyBackupHash.class));
    }

    @Test
    void verify_HashMatches_ReturnsTrue() throws Exception {
        // given
        mockValidHashInRepository();

        // when
        sut.verify(VALID_DATA);
    }

    @Test
    void verify_EntityDoesNotExist_Throws() {
        // given
        mockEmptyHashRepository();

        // when
        assertThrows(SealingKeyBackupHashDoesNotExistException.class, () -> sut.verify(VALID_DATA));
    }

    @Test
    void verify_HashDoesNotMatch_ReturnsFalse() {
        // given
        mockValidHashInRepository();

        // when
        assertThrows(SealingKeyBackupHashDoesNotMatchException.class, () -> sut.verify(INVALID_DATA));
    }

    @Test
    void deleteAll_Success() {
        // when
        sut.deleteAll();

        // then
        verify(sealingKeyBackupHashRepository).deleteAll();
    }

    private void mockEmptyHashRepository() {
        when(sealingKeyBackupHashRepository.findFirstByOrderByIdDesc()).thenReturn(Optional.empty());
    }

    private void mockValidHashInRepository() {
        when(sealingKeyBackupHashRepository.findFirstByOrderByIdDesc()).thenReturn(Optional.of(validEntity));
    }
}
