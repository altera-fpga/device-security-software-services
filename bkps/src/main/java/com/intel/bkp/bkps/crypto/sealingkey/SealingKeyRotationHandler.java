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
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.crypto.rsa.RsaEncryptionProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.PublicKey;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static lombok.AccessLevel.PACKAGE;

@Component
@RequiredArgsConstructor(access = PACKAGE)
@Slf4j
public class SealingKeyRotationHandler {

    private final SealingKeyManager sealingKeyManager;
    private final SealingKeyRotationTransaction sealingKeyRotationTransaction;
    private final SealingKeyBackupHashManager sealingKeyBackupHashManager;
    private final ISecurityProvider securityService;
    private final ImportKeyManager importKeyManager;
    private final SealingKeyRestoreTransaction sealingKeyRestoreTransaction;

    public void rotate() throws SealingKeyRotationException {
        try {
            final SecretKey activeKey = sealingKeyManager.getActiveKey();
            sealingKeyManager.createPendingKey();
            final SecretKey pendingKey = sealingKeyManager.getPendingKey();

            sealingKeyRotationTransaction.reencryptAllAssetsAndActivatePendingKey(activeKey, pendingKey);
        } catch (Exception e) {
            cleanUpPendingKey();
            throw new SealingKeyRotationException(e);
        }
    }

    public String backup(byte[] rsaImportPubKey) throws SealingKeyRotationException {
        try {
            final SecretKey activeKey = sealingKeyManager.getActiveKey();
            final SecretKey backupKey = sealingKeyManager.createExportablePendingKey();
            final SecretKey pendingKey = sealingKeyManager.getPendingKey();

            final byte[] encryptedBackupKey = encryptBackupKeyWithImportPubKey(rsaImportPubKey, backupKey);

            sealingKeyRotationTransaction.reencryptAllAssetsAndActivatePendingKey(activeKey, pendingKey);
            sealingKeyBackupHashManager.update(encryptedBackupKey);

            return toHex(encryptedBackupKey);
        } catch (Exception e) {
            cleanUpPendingKey();
            throw new SealingKeyRotationException(e);
        }
    }

    public void restore(String encryptedSealingKey) throws SealingKeyRotationException,
        SealingKeyBackupHashDoesNotMatchException, SealingKeyBackupHashDoesNotExistException {

        byte[] encryptedKeyBytes = fromHex(encryptedSealingKey);
        sealingKeyBackupHashManager.verify(encryptedKeyBytes);

        try {
            String importKeyAlias = importKeyManager.getImportKeyAlias();
            byte[] restoreKeyBytes = securityService.decryptRSA(importKeyAlias, encryptedKeyBytes);
            SecretKey restoreKey = CryptoUtils.genAesKeyFromByteArray(restoreKeyBytes);
            sealingKeyManager.importSecretKeyAsPending(restoreKey);
            sealingKeyRestoreTransaction.activatePendingKeyAndClearBackup();
        } catch (Exception e) {
            cleanUpPendingKey();
            throw new SealingKeyRotationException(e);
        }
    }

    private byte[] encryptBackupKeyWithImportPubKey(byte[] rsaImportPubKey, SecretKey backupKey)
        throws EncryptionProviderException, KeystoreGenericException {

        final byte[] backupKeyBytes = backupKey.getEncoded();
        final PublicKey rsaImportPublicKey = CryptoUtils.restoreRSAPubKeyBC(rsaImportPubKey);

        RsaEncryptionProvider rsaEncryptionProvider = new RsaEncryptionProvider(rsaImportPublicKey,
            CryptoUtils.getBouncyCastleProvider(), CryptoConstants.RSA_CIPHER_TYPE);
        return rsaEncryptionProvider.encrypt(backupKeyBytes);
    }

    private void cleanUpPendingKey() {
        sealingKeyManager.disablePendingKey();
    }
}
