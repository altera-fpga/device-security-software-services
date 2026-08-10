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

package com.intel.bkp.bkps.crypto.aesgcm;

import com.intel.bkp.bkps.crypto.contextkey.WrappingKeyManager;
import com.intel.bkp.bkps.domain.WrappingKey;
import com.intel.bkp.crypto.aesgcm.AesGcmProvider;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.ByteOrder;
import java.security.Provider;
import java.util.Optional;

import static lombok.AccessLevel.PACKAGE;

@Service
@RequiredArgsConstructor(access = PACKAGE)
@Slf4j
public class AesGcmWrappingKeyProviderImpl extends AesGcmProvider {

    private final WrappingKeyManager wrappingKeyManager;

    private WrappingKey wrappingKey;

    /**
     * This method must be invoked before using provider.
     */
    public void initialize(WrappingKey wrappingKey) throws EncryptionProviderException {
        this.wrappingKey = Optional.ofNullable(wrappingKey)
            .orElseThrow(() -> new EncryptionProviderException("Wrapping Key cannot be null."));
    }

    @Override
    public SecretKey getSecretKey() {
        return wrappingKeyManager.getSecretKeyFrom(wrappingKey);
    }

    @Override
    public Provider getProvider() {
        return wrappingKeyManager.getProvider();
    }

    @Override
    public String getCipherType() {
        return wrappingKeyManager.getCipherType();
    }

    @Override
    public ByteOrder getByteOrder() {
        return ByteOrder.BIG_ENDIAN;
    }

}
