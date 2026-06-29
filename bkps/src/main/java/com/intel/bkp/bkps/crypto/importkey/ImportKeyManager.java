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

package com.intel.bkp.bkps.crypto.importkey;

import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.crypto.constants.SecurityKeyType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import static lombok.AccessLevel.PACKAGE;

@Component
@RequiredArgsConstructor(access = PACKAGE)
@Slf4j
public class ImportKeyManager {

    private final ISecurityProvider securityService;

    static final String IMPORT_KEY_ALIAS = "bkps_import_key";

    public void create() {
        createImportKeyInSecureEnclave();
        verifyIfKeyCreatedSuccessfully();
    }

    public void delete() {
        deleteImportKeyFromSecureEnclave();
    }

    public boolean exists() {
        return isPresentInSecurityEnclave();
    }

    public String getImportKeyAlias() {
        return IMPORT_KEY_ALIAS;
    }

    public byte[] getPublicKey() {
        return securityService.getPubKeyFromSecurityObject(getImportKeyAlias());
    }

    private boolean isPresentInSecurityEnclave() {
        return securityService.existsSecurityObject(getImportKeyAlias());
    }

    private void createImportKeyInSecureEnclave() {
        securityService.createSecurityObject(SecurityKeyType.RSA, getImportKeyAlias());
    }

    private void deleteImportKeyFromSecureEnclave() {
        securityService.deleteSecurityObject(getImportKeyAlias());
    }

    private void verifyIfKeyCreatedSuccessfully() {
        if (!securityService.existsSecurityObject(getImportKeyAlias())) {
            throw new BKPInternalServerException(ErrorCodeMap.FAILED_TO_SAVE_IMPORT_KEY_IN_SECURITY_ENCLAVE);
        }
    }
}
