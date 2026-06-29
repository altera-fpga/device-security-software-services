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

package com.intel.bkp.bkps.crypto.aesctr;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.aesctr.AesCounterModeProvider;
import com.intel.bkp.crypto.aesctr.IIvProvider;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.security.Provider;

@AllArgsConstructor
@Slf4j
public class AesCtrSigmaEncProviderImpl extends AesCounterModeProvider {

    private static final String BOUNCE_CASTLE_CIPHER_TYPE = "AES/CTR/NoPadding";

    private final byte[] sessionEncryptionKey;
    private final IIvProvider aesCtrIvProvider;

    @Override
    public SecretKey getSecretKey() {
        return CryptoUtils.genAesKeyFromByteArray(sessionEncryptionKey);
    }

    @Override
    public Provider getProvider() {
        return CryptoUtils.getBouncyCastleProvider();
    }

    @Override
    public String getCipherType() {
        return BOUNCE_CASTLE_CIPHER_TYPE;
    }

    @Override
    public IIvProvider getIvProvider() {
        return aesCtrIvProvider;
    }
}
