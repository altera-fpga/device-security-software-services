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
import com.intel.bkp.bkps.exception.ContextKeyException;
import com.intel.bkp.bkps.repository.ContextKeyRepository;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.security.Provider;

import static lombok.AccessLevel.PACKAGE;

@Service
@RequiredArgsConstructor(access = PACKAGE)
@Slf4j
public class ContextKeyManager {

    private final ContextKeyRepository contextKeyRepository;
    private final ContextKeyWrapper contextKeyWrapper;
    private final ContextKeySyncService contextKeySyncService;

    @Setter
    @Getter
    private UnwrappedContextKey unwrappedContextKey;

    @Transactional(isolation = Isolation.SERIALIZABLE)
    public SecretKey get() {
        log.debug("Get ContextKey.");
        if (isInvalid()) {
            unwrappedContextKey = initialize();
        }
        return unwrappedContextKey.getSecretKey();
    }

    @Transactional(isolation = Isolation.SERIALIZABLE)
    public void rotate() {
        log.info("Rotating ContextKey.");
        unwrappedContextKey = createNewKey();
    }

    public Provider getProvider() {
        return CryptoUtils.getBouncyCastleProvider();
    }

    public String getCipherType() {
        return CryptoConstants.AES_CIPHER_TYPE;
    }

    private boolean isInvalid() {
        return unwrappedContextKey == null || !contextKeySyncService.inSync(unwrappedContextKey);
    }

    private UnwrappedContextKey initialize() {
        log.debug("Initialize ContextKey.");
        return contextKeyRepository.getActualContextKey()
            .map(this::unwrapKey)
            .orElseGet(this::createNewKey);
    }

    private UnwrappedContextKey unwrapKey(ContextKey key) {
        try {
            log.debug("ContextKey exists in DB - unwrapping.");
            return UnwrappedContextKey.instance(key, contextKeyWrapper.unwrap(key));
        } catch (EncryptionProviderException e) {
            throw new ContextKeyException("Could not unwrap AES context key.", e);
        }
    }

    private UnwrappedContextKey createNewKey() {
        log.debug("Creating new ContextKey.");
        final SecretKey secretKey = createKey();
        final ContextKey contextKey = saveWrappedContextKeyToDB(secretKey);
        return UnwrappedContextKey.instance(contextKey, secretKey);
    }

    private SecretKey createKey() {
        try {
            return CryptoUtils.genAesBC();
        } catch (KeystoreGenericException e) {
            throw new ContextKeyException("Could not create AES context key with BouncyCastle.", e);
        }
    }

    private ContextKey saveWrappedContextKeyToDB(SecretKey secretKey) {
        try {
            final ContextKey wrappedKey = contextKeyWrapper.wrap(secretKey);
            return contextKeyRepository.save(wrappedKey);
        } catch (EncryptionProviderException e) {
            throw new ContextKeyException("Could not wrap AES context key.", e);
        }
    }

}
