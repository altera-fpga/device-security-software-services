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

import com.intel.bkp.bkps.domain.WrappingKey;
import com.intel.bkp.bkps.domain.enumeration.WrappingKeyType;
import com.intel.bkp.bkps.exception.WrappingKeyException;
import com.intel.bkp.bkps.repository.WrappingKeyRepository;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.crypto.constants.SecurityKeyType;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.security.Provider;
import java.util.Optional;
import java.util.UUID;

import static lombok.AccessLevel.PACKAGE;

@Slf4j
@Service
@AllArgsConstructor(access = PACKAGE)
public class WrappingKeyManager {

    private final ISecurityProvider securityService;
    private final WrappingKeyRepository wrappingKeyRepository;

    @Transactional(isolation = Isolation.SERIALIZABLE)
    public WrappingKey getKey() {
        log.debug("Get WrappingKey.");
        return getWrappingKeyFromRepository()
            .filter(this::existsInSecurityEnclave)
            .orElseGet(this::createKey);
    }

    @Transactional(isolation = Isolation.SERIALIZABLE)
    public void rotate() {
        log.info("Rotating WrappingKey.");
        getWrappingKeyFromRepository().ifPresent(k -> removeFromSecurityEnclave(k.getGuid()));
    }

    public SecretKey getSecretKeyFrom(WrappingKey wrappingKey) {
        log.debug("Get secret key from WrappingKey.");
        return getSecretKeyFromEnclave(wrappingKey);
    }

    public Provider getProvider() {
        return securityService.getProvider();
    }

    public String getCipherType() {
        return securityService.getAesCipherType();
    }

    private Optional<WrappingKey> getWrappingKeyFromRepository() {
        return wrappingKeyRepository.getActualWrappingKey();
    }

    private boolean existsInSecurityEnclave(WrappingKey key) {
        return existsInSecurityEnclave(key.getGuid());
    }

    private boolean existsInSecurityEnclave(String keyAlias) {
        log.debug("Verifying if WrappingKey exists in security enclave: " + keyAlias);
        return securityService.existsSecurityObject(keyAlias);
    }

    private void removeFromSecurityEnclave(String keyAlias) {
        if (existsInSecurityEnclave(keyAlias)) {
            securityService.deleteSecurityObject(keyAlias);
        }
    }

    private WrappingKey createKey() {
        log.debug("Creating new WrappingKey.");
        String securityObjectId = generateNewGuid();
        createNewSecurityObjectInSecureEnclave(securityObjectId);
        verifyIfSealingKeyCreatedSuccessfully(securityObjectId);
        return saveNewKeyInDatabase(securityObjectId);
    }

    private String generateNewGuid() {
        return UUID.randomUUID().toString();
    }

    private void createNewSecurityObjectInSecureEnclave(String securityObjectId) {
        securityService.createSecurityObject(SecurityKeyType.AES, securityObjectId);
    }

    private void verifyIfSealingKeyCreatedSuccessfully(String securityObjectId) {
        if (!securityService.existsSecurityObject(securityObjectId)) {
            throw new WrappingKeyException("Failed to create key in security enclave.");
        }
    }

    private WrappingKey saveNewKeyInDatabase(String securityObjectId) {
        return wrappingKeyRepository.save(
            WrappingKey.builder().guid(securityObjectId).keyType(WrappingKeyType.ACTUAL.name()).build());
    }

    private SecretKey getSecretKeyFromEnclave(WrappingKey key) {
        return getSecretKeyFromEnclave(key.getGuid());
    }

    private SecretKey getSecretKeyFromEnclave(String keyAlias) {
        return securityService.getKeyFromSecurityObject(keyAlias);
    }
}
