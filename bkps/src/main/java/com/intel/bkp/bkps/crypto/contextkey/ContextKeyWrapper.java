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

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmWrappingKeyProviderImpl;
import com.intel.bkp.bkps.domain.ContextKey;
import com.intel.bkp.bkps.domain.WrappingKey;
import com.intel.bkp.bkps.exception.WrappingKeyException;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import dev.failsafe.Failsafe;
import dev.failsafe.RetryPolicy;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.util.Objects;

@Slf4j
@Component
@AllArgsConstructor
public class ContextKeyWrapper {

    private static final int DELAY_SECONDS = 1;
    private static final int MAX_RETRIES = 3;
    private static final RetryPolicy<Object> RETRY_POLICY = RetryPolicy.builder()
        .handle(DataIntegrityViolationException.class)
        .handle(WrappingKeyException.class)
        .handleResultIf(Objects::isNull)
        .withDelay(Duration.ofSeconds(DELAY_SECONDS))
        .withMaxRetries(MAX_RETRIES)
        .build();

    private final AesGcmWrappingKeyProviderImpl aesGcmWrappingProvider;
    private final WrappingKeyManager wrappingKeyManager;


    public ContextKey wrap(SecretKey secretKey) throws EncryptionProviderException {
        log.debug("Performing ContextKey wrapping.");
        WrappingKey wrappingKey = retryableGetKey();
        aesGcmWrappingProvider.initialize(wrappingKey);
        return ContextKey.from(aesGcmWrappingProvider.encrypt(secretKey.getEncoded()), wrappingKey);
    }

    public SecretKey unwrap(ContextKey contextKey) throws EncryptionProviderException {
        log.debug("Performing ContextKey unwrapping.");
        aesGcmWrappingProvider.initialize(contextKey.getWrappingKey());
        return CryptoUtils.genAesKeyFromByteArray(aesGcmWrappingProvider.decrypt(contextKey.decoded()));
    }

    private WrappingKey retryableGetKey() {
        try {
            return Failsafe.with(RETRY_POLICY).get(wrappingKeyManager::getKey);
        } catch (Exception ex) {
            throw new WrappingKeyException(ex);
        }
    }
}
