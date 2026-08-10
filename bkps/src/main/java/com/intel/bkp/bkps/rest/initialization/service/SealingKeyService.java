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
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.initialization.model.dto.EncryptedSealingKeyDTO;
import com.intel.bkp.bkps.rest.initialization.model.dto.SealingKeyResponseDTO;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.crypto.CertificateEncoder;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

import static lombok.AccessLevel.PACKAGE;

@Service
@AllArgsConstructor(access = PACKAGE)
@Slf4j
public class SealingKeyService {

    private final SealingKeyManager sealingKeyManager;
    private final SealingKeyRotationHandler sealingKeyRotationHandler;

    public void createSealingKey() {
        throwIfSealingKeyRotationPending();
        throwIfActiveKeyAlreadyExists();

        log.info("Creating new Sealing Key...");

        sealingKeyManager.createActiveKey();
    }

    public void rotateSealingKey() {
        throwIfSealingKeyRotationPending();
        throwIfNoActiveSealingKey();

        log.info("Starting Sealing Key rotation...");

        try {
            sealingKeyRotationHandler.rotate();
        } catch (Exception e) {
            throw new BKPInternalServerException(ErrorCodeMap.SEALING_KEY_ROTATION_FAILED, e);
        }
    }

    public EncryptedSealingKeyDTO backup(String rsaImportPubKeyPem) {
        throwIfSealingKeyRotationPending();
        throwIfNoActiveSealingKey();

        log.info("Starting to backup all ServiceConfigurations with Backup Sealing Key...");

        try {
            byte[] rsaImportPubKey = getRsaImportPubKeyBytesFromPem(rsaImportPubKeyPem);
            String base64EncodedSealingKey = sealingKeyRotationHandler.backup(rsaImportPubKey);
            return new EncryptedSealingKeyDTO(base64EncodedSealingKey);
        } catch (Exception e) {
            throw new BKPInternalServerException(ErrorCodeMap.SEALING_KEY_BACKUP_FAILED, e);
        }
    }

    public void restore(String encryptedSealingKey) {
        throwIfSealingKeyRotationPending();
        throwIfNoActiveSealingKeyInDatabase();

        log.info("Starting to restore ServiceConfigurations with Backup Sealing Key...");

        try {
            sealingKeyRotationHandler.restore(encryptedSealingKey);
        } catch (SealingKeyBackupHashDoesNotMatchException e) {
            throw new BKPBadRequestException(ErrorCodeMap.SEALING_KEY_BACKUP_HASH_DOES_NOT_MATCH, e);
        } catch (SealingKeyBackupHashDoesNotExistException e) {
            throw new BKPBadRequestException(ErrorCodeMap.SEALING_KEY_BACKUP_HASH_DOES_NOT_EXIST, e);
        } catch (Exception e) {
            throw new BKPInternalServerException(ErrorCodeMap.SEALING_KEY_RESTORE_FAILED, e);
        }
    }

    public List<SealingKeyResponseDTO> getAllSealingKeys() {
        return sealingKeyManager.list();
    }

    private void throwIfNoActiveSealingKey() {
        if (!sealingKeyManager.isActiveSealingKey()) {
            throw new BKPBadRequestException(ErrorCodeMap.ACTIVE_SEALING_KEY_DOES_NOT_EXIST);
        }
    }

    private void throwIfNoActiveSealingKeyInDatabase() {
        if (!sealingKeyManager.isActiveSealingKeyInDatabase()) {
            throw new BKPBadRequestException(ErrorCodeMap.ACTIVE_SEALING_KEY_DOES_NOT_EXIST);
        }
    }

    private void throwIfActiveKeyAlreadyExists() {
        if (sealingKeyManager.isActiveSealingKey()) {
            throw new BKPBadRequestException(ErrorCodeMap.ACTIVE_SEALING_KEY_ALREADY_EXISTS);
        }
    }

    private void throwIfSealingKeyRotationPending() {
        if (sealingKeyManager.isPendingSealingKey()) {
            throw new BKPBadRequestException(ErrorCodeMap.SEALING_KEY_ROTATION_PENDING);
        }
    }

    private byte[] getRsaImportPubKeyBytesFromPem(String rsaImportPubKeyPem) {
        return CertificateEncoder.sanitizeChainPayloadBase64(rsaImportPubKeyPem);
    }
}
