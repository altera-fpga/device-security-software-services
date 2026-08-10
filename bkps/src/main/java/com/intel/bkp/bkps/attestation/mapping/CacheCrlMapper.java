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

package com.intel.bkp.bkps.attestation.mapping;

import com.intel.bkp.crypto.exceptions.X509CrlParsingException;
import com.intel.bkp.crypto.x509.parsing.X509CrlParser;
import com.intel.bkp.crypto.x509.utils.X509CrlUtils;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509CRL;
import java.util.Optional;

@Slf4j
public class CacheCrlMapper implements CacheObjectMapper<X509CRL> {

    @SneakyThrows
    @Override
    public String encode(X509CRL obj) {
        return X509CrlUtils.toPem(obj);
    }

    @Override
    public X509CRL decode(String content) {
        try {
            return X509CrlParser.pemToX509Crl(content);
        } catch (X509CrlParsingException e) {
            log.error("Failed to parse content", e);
            return null;
        }
    }

    @Override
    public Optional<X509CRL> parse(byte[] bytes) {
        return X509CrlParser.tryToX509(bytes);
    }
}
