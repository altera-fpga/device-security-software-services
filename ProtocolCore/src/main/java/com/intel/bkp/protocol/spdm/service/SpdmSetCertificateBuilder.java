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

package com.intel.bkp.protocol.spdm.service;

import com.intel.bkp.protocol.spdm.exceptions.SpdmRuntimeException;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.utils.ByteSwapOrder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;

import java.nio.ByteBuffer;
import java.util.List;

import static com.intel.bkp.utils.HexConverter.toFormattedHex;
import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
@Getter
public class SpdmSetCertificateBuilder {

    private static final int SET_CERT_RESERVED_FIELD_LEN = 2;
    private static final int WORD_SIZE = 4;

    private final byte[] reserved = new byte[SET_CERT_RESERVED_FIELD_LEN];
    private short lenOfCertChain;
    private ByteBuffer certChainBuffer;

    public SpdmSetCertificateBuilder parse(List<byte[]> certificateChain) {
        final byte[] rootCertHash = getRootCertHash(certificateChain);

        lenOfCertChain = (short) (reserved.length + Short.BYTES + rootCertHash.length
            + certificateChain.stream().mapToInt(c -> c.length).sum());
        final int lenOfCertChainInBytesWithPadding = getLenOfCertChainInBytesWithPadding(lenOfCertChain);

        certChainBuffer = ByteBuffer.allocate(lenOfCertChainInBytesWithPadding)
            .putShort(ByteSwap.getSwappedShort(lenOfCertChain, ByteSwapOrder.B2L))
            .put(reserved)
            .put(rootCertHash);

        certificateChain.forEach(certChainBuffer::put);
        certChainBuffer.rewind();

        return this;
    }

    public byte[] build() {
        final byte[] array = certChainBuffer.array();
        log.trace("SPDM Certificate (len in bytes with padding: {}): {}", array.length, toHex(array));
        return array;
    }

    private static byte[] getRootCertHash(List<byte[]> certificateChain) {
        if (certificateChain.isEmpty()) {
            throw new SpdmRuntimeException("Certificate chain for Set Authority is empty.");
        }

        final byte[] rootCertHash = DigestUtils.sha384(certificateChain.get(0));
        log.debug("Calculated ROOT Cert Chain Hash: {}", toHex(rootCertHash));
        return rootCertHash;
    }

    private static int getLenOfCertChainInBytesWithPadding(short lenOfCertChain) {
        final int lenOfCertChainInWords = lenOfCertChain % WORD_SIZE == 0
                                          ? lenOfCertChain / WORD_SIZE
                                          : lenOfCertChain / WORD_SIZE + 1;
        final int lenOfCertChainInBytesWithPadding = lenOfCertChainInWords * WORD_SIZE;
        log.debug("Calculated Cert Chain Len: {} ({}) bytes. "
                + "Total cert chain len with padding: {} ({}) or {} ({}) words;",
            lenOfCertChain, toFormattedHex(lenOfCertChain),
            lenOfCertChainInBytesWithPadding, toFormattedHex(lenOfCertChainInBytesWithPadding),
            lenOfCertChainInWords, toFormattedHex(lenOfCertChainInWords)
        );
        return lenOfCertChainInBytesWithPadding;
    }

}
