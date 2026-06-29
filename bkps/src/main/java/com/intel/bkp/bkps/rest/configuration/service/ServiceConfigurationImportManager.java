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

package com.intel.bkp.bkps.rest.configuration.service;

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmImportConfigurationProviderImpl;
import com.intel.bkp.bkps.crypto.importkey.ImportKeyManager;
import com.intel.bkp.bkps.domain.ConfidentialData;
import com.intel.bkp.bkps.domain.EncryptedAesImportKey;
import com.intel.bkp.bkps.domain.EncryptedQekImportKey;
import com.intel.bkp.bkps.exception.ServiceImportKeyNotExistException;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static lombok.AccessLevel.PACKAGE;

@Service
@Transactional(isolation = Isolation.SERIALIZABLE)
@AllArgsConstructor(access = PACKAGE)
public class ServiceConfigurationImportManager {

    private final ISecurityProvider securityService;
    private final ImportKeyManager importKeyManager;

    private AesGcmImportConfigurationProviderImpl decryptionProvider = new AesGcmImportConfigurationProviderImpl();

    @Autowired
    ServiceConfigurationImportManager(ISecurityProvider securityService, ImportKeyManager importKeyManager) {
        this.securityService = securityService;
        this.importKeyManager = importKeyManager;
    }

    public void decrypt(ConfidentialData confidentialData) {
        throwIfImportKeyDoesNotExist();
        byte[] decryptionAesKey = decryptEncryptionKey(Optional.ofNullable(confidentialData.getEncryptedAesKey())
            .orElseThrow(() -> new BKPBadRequestException(ErrorCodeMap.MISSING_ENCRYPTED_AES_KEY)));
        decryptionProvider.initialize(decryptionAesKey);
        confidentialData.getAesKey().setValue(decryptInternal(confidentialData.getAesKey().getValue()));
        if (confidentialData.getQek() != null) {
            byte[] decryptionQekKey = decryptEncryptionKey(Optional.ofNullable(confidentialData.getEncryptedQek())
                .orElseThrow(() -> new BKPBadRequestException(ErrorCodeMap.MISSING_ENCRYPTED_QEK)));
            decryptionProvider.initialize(decryptionQekKey);
            confidentialData.getQek().setValue(decryptInternal(confidentialData.getQek().getValue()));
        }
    }

    private void throwIfImportKeyDoesNotExist() {
        if (!importKeyManager.exists()) {
            throw new ServiceImportKeyNotExistException();
        }
    }

    private byte[] decryptEncryptionKey(EncryptedQekImportKey encryptedQekImportKey) {
        return securityService.decryptRSA(importKeyManager.getImportKeyAlias(),
            fromHex(encryptedQekImportKey.getValue())
        );
    }

    private byte[] decryptEncryptionKey(EncryptedAesImportKey encryptedAesImportKey) {
        return securityService.decryptRSA(importKeyManager.getImportKeyAlias(),
            fromHex(encryptedAesImportKey.getValue())
        );
    }

    private String decryptInternal(String data) {
        try {
            return toHex(decryptionProvider.decrypt(fromHex(data)));
        } catch (EncryptionProviderException e) {
            throw new BKPBadRequestException(ErrorCodeMap.FAILED_TO_DECRYPT_UPLOADED_SENSITIVE_DATA, e);
        }
    }
}
