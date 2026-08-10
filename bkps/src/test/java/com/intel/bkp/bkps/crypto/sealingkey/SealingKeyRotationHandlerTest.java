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

import com.intel.bkp.bkps.crypto.importkey.ImportKeyManager;
import com.intel.bkp.bkps.exception.SealingKeyBackupHashDoesNotExistException;
import com.intel.bkp.bkps.exception.SealingKeyBackupHashDoesNotMatchException;
import com.intel.bkp.bkps.exception.SealingKeyRotationException;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.Provider;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class SealingKeyRotationHandlerTest {

    @Mock
    private SecretKey secretKeyActive;

    @Mock
    private SecretKey secretKeyPending;

    @Mock
    private SecretKey secretKeyBackup;

    @Mock
    private SealingKeyManager sealingKeyManager;

    @Mock
    private SealingKeyRotationTransaction sealingKeyRotationTransaction;

    @Mock
    private SealingKeyBackupHashManager sealingKeyBackupHashManager;

    @Mock
    private ISecurityProvider securityService;

    @Mock
    private ImportKeyManager importKeyManager;

    @Mock
    private SealingKeyRestoreTransaction sealingKeyRestoreTransaction;

    @InjectMocks
    private SealingKeyRotationHandler sut;

    private static final Provider BOUNCY_CASTLE_PROVIDER = CryptoUtils.getBouncyCastleProvider();
    private static final String IMPORT_KEY_ALIAS = "alias";
    private static final String ENCRYPTED_SEALING_KEY = "0102";

    @BeforeEach
    void setUp() {
        when(secretKeyBackup.getEncoded()).thenReturn(new byte[32]);
        when(importKeyManager.getImportKeyAlias()).thenReturn(IMPORT_KEY_ALIAS);
        when(securityService.decryptRSA(eq(IMPORT_KEY_ALIAS), any())).thenReturn(new byte[32]);
    }

    @Test
    void rotate_Success() throws Exception {
        // given
        mockActiveKey();
        mockPendingKey();

        // when
        sut.rotate();

        // then
        verify(sealingKeyManager).createPendingKey();
        verify(sealingKeyRotationTransaction).reencryptAllAssetsAndActivatePendingKey(secretKeyActive,
            secretKeyPending);
    }

    @Test
    void rotate_ThrowsException_CleanupPendingAndThrow() {
        // given
        mockActiveKey();
        mockPendingKey();

        doThrow(new RuntimeException())
            .when(sealingKeyRotationTransaction)
            .reencryptAllAssetsAndActivatePendingKey(secretKeyActive, secretKeyPending);

        // when
        assertThrows(SealingKeyRotationException.class,
            () -> sut.rotate()
        );

        // then
        verify(sealingKeyManager).disablePendingKey();
    }

    @Test
    void backup_Success() throws Exception {
        // given
        mockActiveKey();
        mockExportablePendingKey();
        mockPendingKey();
        byte[] rsaImportPublicKey = getRsaPublicKey();

        // when
        String result = sut.backup(rsaImportPublicKey);

        // then
        assertNotNull(result);

        verify(sealingKeyRotationTransaction).reencryptAllAssetsAndActivatePendingKey(secretKeyActive,
            secretKeyPending);
        verify(sealingKeyBackupHashManager).update(any());
    }

    @Test
    void backup_ThrowsException_CleanupPendingAndThrow() throws Exception {
        // given
        mockActiveKey();
        mockExportablePendingKey();
        mockPendingKey();
        byte[] rsaImportPublicKey = getRsaPublicKey();

        doThrow(new RuntimeException())
            .when(sealingKeyRotationTransaction)
            .reencryptAllAssetsAndActivatePendingKey(secretKeyActive, secretKeyPending);

        // when
        assertThrows(SealingKeyRotationException.class,
            () -> sut.backup(rsaImportPublicKey)
        );

        // then
        verify(sealingKeyManager).disablePendingKey();
    }

    @Test
    void restore_Success() throws Exception {
        // when
        sut.restore(ENCRYPTED_SEALING_KEY);

        // then
        verify(sealingKeyBackupHashManager).verify(any());
        verify(importKeyManager).getImportKeyAlias();
        verify(securityService).decryptRSA(any(), any());
        verify(sealingKeyManager).importSecretKeyAsPending(any());
        verify(sealingKeyRestoreTransaction).activatePendingKeyAndClearBackup();
    }

    @Test
    void restore_BackupHashDoesNotExist_Throws() throws Exception {
        // given
        mockHashDoesNotExist();

        // when
        assertThrows(SealingKeyBackupHashDoesNotExistException.class,
            () -> sut.restore(ENCRYPTED_SEALING_KEY)
        );
    }

    @Test
    void restore_BackupHashDoesNotMatch_Throws() throws Exception {
        // given
        mockHashDoesNotMatch();

        // when
        assertThrows(SealingKeyBackupHashDoesNotMatchException.class,
            () -> sut.restore(ENCRYPTED_SEALING_KEY)
        );
    }

    @Test
    void restore_ExceptionIsThrow_Throws() {
        // given
        doThrow(new RuntimeException()).when(securityService).decryptRSA(any(), any());

        // when
        assertThrows(SealingKeyRotationException.class,
            () -> sut.restore(ENCRYPTED_SEALING_KEY)
        );

        // then
        verify(sealingKeyManager).disablePendingKey();
    }

    private void mockActiveKey() {
        when(sealingKeyManager.getActiveKey()).thenReturn(secretKeyActive);
    }

    private void mockPendingKey() {
        when(sealingKeyManager.getPendingKey()).thenReturn(secretKeyPending);
    }

    private void mockExportablePendingKey() throws KeystoreGenericException {
        when(sealingKeyManager.createExportablePendingKey()).thenReturn(secretKeyBackup);
    }

    private byte[] getRsaPublicKey() throws KeystoreGenericException {
        final KeyPair rsaKeyPair = CryptoUtils.genRsaBC();
        return rsaKeyPair.getPublic().getEncoded();
    }

    private void mockHashDoesNotExist() throws Exception {
        doThrow(new SealingKeyBackupHashDoesNotExistException()).when(sealingKeyBackupHashManager).verify(any());
    }

    private void mockHashDoesNotMatch() throws Exception {
        doThrow(new SealingKeyBackupHashDoesNotMatchException()).when(sealingKeyBackupHashManager).verify(any());
    }
}
