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

package com.intel.bkp.bkps.rest.initialization.service;

import com.intel.bkp.bkps.crypto.sealingkey.SealingKeyManager;
import com.intel.bkp.bkps.crypto.sealingkey.SealingKeyRotationHandler;
import com.intel.bkp.bkps.exception.SealingKeyBackupHashDoesNotExistException;
import com.intel.bkp.bkps.exception.SealingKeyBackupHashDoesNotMatchException;
import com.intel.bkp.bkps.exception.SealingKeyRotationException;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.initialization.model.dto.EncryptedSealingKeyDTO;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.intel.bkp.test.AssertionUtils.verifyExpectedErrorCode;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class SealingKeyServiceTest {

    private static final String TEST_PUB_KEY = "pubKey";
    private static final String TEST_ENCODED_KEY = "Test";
    private static final RuntimeException TEST_CAUSE = new RuntimeException();

    @Mock
    private SealingKeyManager sealingKeyManager;

    @Mock
    private SealingKeyRotationHandler sealingKeyRotationHandler;

    @InjectMocks
    private SealingKeyService sut;

    @Test
    void createSealingKey_Success() {
        // given
        mockPendingSealingKeyDoesNotExist();
        mockActiveSealingKeyDoesNotExist();

        // when
        sut.createSealingKey();

        // then
        verify(sealingKeyManager).createActiveKey();
    }

    @Test
    void createSealingKey_PendingExists_Throws() {
        // given
        mockPendingSealingKeyExists();

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.createSealingKey()
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.SEALING_KEY_ROTATION_PENDING);
    }

    @Test
    void createSealingKey_ActiveExists_Throws() {
        // given
        mockPendingSealingKeyDoesNotExist();
        mockActiveSealingKeyExists();

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.createSealingKey()
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.ACTIVE_SEALING_KEY_ALREADY_EXISTS);
    }

    @Test
    void rotateSealingKey_Success() throws Exception {
        // given
        mockPendingSealingKeyDoesNotExist();
        mockActiveSealingKeyExists();

        // when
        sut.rotateSealingKey();

        // then
        verify(sealingKeyRotationHandler).rotate();
    }

    @Test
    void rotateSealingKey_PendingExists_Throws() {
        // given
        mockPendingSealingKeyExists();

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.rotateSealingKey()
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.SEALING_KEY_ROTATION_PENDING);
    }

    @Test
    void rotateSealingKey_ActiveDoesNotExist_Success() {
        // given
        mockPendingSealingKeyDoesNotExist();
        mockActiveSealingKeyDoesNotExist();

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.rotateSealingKey()
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.ACTIVE_SEALING_KEY_DOES_NOT_EXIST);
    }

    @Test
    void rotateSealingKey_ExceptionIsThrown_Throws() throws Exception {
        // given
        mockPendingSealingKeyDoesNotExist();
        mockActiveSealingKeyExists();

        doThrow(new SealingKeyRotationException(TEST_CAUSE)).when(sealingKeyRotationHandler).rotate();

        // when-then
        final BKPInternalServerException exception = assertThrows(BKPInternalServerException.class,
            () -> sut.rotateSealingKey()
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.SEALING_KEY_ROTATION_FAILED);
    }

    @Test
    void backup_Success() throws Exception {
        // given
        mockPendingSealingKeyDoesNotExist();
        mockActiveSealingKeyExists();
        mockBackupReturnsEncodedSealingKey(TEST_ENCODED_KEY);

        // when
        EncryptedSealingKeyDTO result = sut.backup(TEST_PUB_KEY);

        // then
        assertNotNull(result);
        assertEquals(TEST_ENCODED_KEY, result.getEncryptedSealingKey());
    }

    @Test
    void backup_PendingExists_Throws() {
        // given
        mockPendingSealingKeyExists();

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.backup(TEST_PUB_KEY)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.SEALING_KEY_ROTATION_PENDING);
    }

    @Test
    void backup_ActiveDoesNotExist_Throws() {
        // given
        mockPendingSealingKeyDoesNotExist();
        mockActiveSealingKeyDoesNotExist();

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.backup(TEST_PUB_KEY)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.ACTIVE_SEALING_KEY_DOES_NOT_EXIST);
    }

    @Test
    void backup_RotationHandlerFails_Throws() throws Exception {
        // given
        mockPendingSealingKeyDoesNotExist();
        mockActiveSealingKeyExists();
        doThrow(new SealingKeyRotationException(TEST_CAUSE)).when(sealingKeyRotationHandler).backup(any());

        // when-then
        final BKPInternalServerException exception = assertThrows(BKPInternalServerException.class,
            () -> sut.backup(TEST_PUB_KEY)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.SEALING_KEY_BACKUP_FAILED);
    }

    @Test
    void restore_Success() throws Exception {
        // given
        mockPendingSealingKeyDoesNotExist();
        mockActiveSealingKeyExistsInDatabase();

        // when
        sut.restore(TEST_ENCODED_KEY);

        // then
        verify(sealingKeyRotationHandler).restore(TEST_ENCODED_KEY);
    }

    @Test
    void restore_PendingExists_Throws() {
        // given
        mockPendingSealingKeyExists();

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.restore(TEST_ENCODED_KEY)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.SEALING_KEY_ROTATION_PENDING);
    }

    @Test
    void restore_ActiveDoesNotExist_Throws() {
        // given
        mockPendingSealingKeyDoesNotExist();
        mockActiveSealingKeyDoesNotExistInDatabase();

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.restore(TEST_ENCODED_KEY)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.ACTIVE_SEALING_KEY_DOES_NOT_EXIST);
    }

    @Test
    void restore_RotationHandlerFails_Throws() throws Exception {
        // given
        mockPendingSealingKeyDoesNotExist();
        mockActiveSealingKeyExistsInDatabase();
        doThrow(new SealingKeyRotationException(TEST_CAUSE)).when(sealingKeyRotationHandler).restore(any());

        // when-then
        final BKPInternalServerException exception = assertThrows(BKPInternalServerException.class,
            () -> sut.restore(TEST_ENCODED_KEY)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.SEALING_KEY_RESTORE_FAILED);
    }

    @Test
    void restore_RotationHandlerFailsDueToHashNotExists_Throws() throws Exception {
        // given
        mockPendingSealingKeyDoesNotExist();
        mockActiveSealingKeyExistsInDatabase();
        doThrow(new SealingKeyBackupHashDoesNotExistException()).when(sealingKeyRotationHandler).restore(any());

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.restore(TEST_ENCODED_KEY)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.SEALING_KEY_BACKUP_HASH_DOES_NOT_EXIST);
    }

    @Test
    void restore_RotationHandlerFailsWithHashNotMatch_Throws() throws Exception {
        // given
        mockPendingSealingKeyDoesNotExist();
        mockActiveSealingKeyExistsInDatabase();
        doThrow(new SealingKeyBackupHashDoesNotMatchException()).when(sealingKeyRotationHandler).restore(any());

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.restore(TEST_ENCODED_KEY)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.SEALING_KEY_BACKUP_HASH_DOES_NOT_MATCH);
    }

    @Test
    void getAllSealingKeys_Success() {
        // when
        sut.getAllSealingKeys();

        // then
        verify(sealingKeyManager).list();
    }

    private void mockActiveSealingKeyExists() {
        when(sealingKeyManager.isActiveSealingKey()).thenReturn(true);
    }

    private void mockActiveSealingKeyExistsInDatabase() {
        when(sealingKeyManager.isActiveSealingKeyInDatabase()).thenReturn(true);
    }

    private void mockActiveSealingKeyDoesNotExist() {
        when(sealingKeyManager.isActiveSealingKey()).thenReturn(false);
    }

    private void mockActiveSealingKeyDoesNotExistInDatabase() {
        when(sealingKeyManager.isActiveSealingKeyInDatabase()).thenReturn(false);
    }

    private void mockPendingSealingKeyExists() {
        when(sealingKeyManager.isPendingSealingKey()).thenReturn(true);
    }

    private void mockPendingSealingKeyDoesNotExist() {
        when(sealingKeyManager.isPendingSealingKey()).thenReturn(false);
    }

    private void mockBackupReturnsEncodedSealingKey(String expectedSealingKey) throws Exception {
        when(sealingKeyRotationHandler.backup(any())).thenReturn(expectedSealingKey);
    }
}
