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

import com.intel.bkp.bkps.crypto.importkey.ImportKeyManager;
import com.intel.bkp.bkps.exception.ServiceImportKeyNotExistException;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.SecurityKeyType;
import com.intel.bkp.crypto.pem.PemFormatEncoder;
import com.intel.bkp.crypto.pem.PemFormatHeader;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import static lombok.AccessLevel.PACKAGE;

/**
 * Service Implementation for managing ImportKey.
 */
@Service
@Transactional(isolation = Isolation.SERIALIZABLE)
@AllArgsConstructor(access = PACKAGE)
@Slf4j
public class ImportKeyService {

    private final ImportKeyManager importKeyManager;

    public String getServiceImportPublicKey() {
        throwIfImportKeyDoesNotExist();

        byte[] pubKeyBytes = importKeyManager.getPublicKey();
        try {
            PublicKey publicKey = CryptoUtils.toPublicEncodedBC(pubKeyBytes, SecurityKeyType.RSA.name());
            return PemFormatEncoder.encode(PemFormatHeader.PUBLIC_KEY, publicKey.getEncoded());
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new BKPInternalServerException(ErrorCodeMap.UNABLE_TO_RETRIEVE_PUBLIC_KEY, e);
        }
    }

    private void throwIfImportKeyDoesNotExist() {
        if (!importKeyManager.exists()) {
            throw new ServiceImportKeyNotExistException();
        }
    }
}
