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

import com.intel.bkp.fpgacerts.cbor.CborObjectParser;
import com.upokecenter.cbor.CBORObject;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
public class CacheCborMapper implements CacheObjectMapper<CBORObject> {

    @Override
    public String encode(CBORObject obj) {
        return toHex(obj.EncodeToBytes());
    }

    @Override
    public CBORObject decode(String content) {
        return parse(fromHex(content)).orElse(null);
    }

    @Override
    public Optional<CBORObject> parse(byte[] bytes) {
        try {
            return Optional.of(CborObjectParser.instance().parse(bytes));
        } catch (Exception e) {
            log.debug("Failed to parse fetched CBOR object.", e);
            return Optional.empty();
        }
    }
}
