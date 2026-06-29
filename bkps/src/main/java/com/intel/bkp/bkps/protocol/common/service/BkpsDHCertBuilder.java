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

package com.intel.bkp.bkps.protocol.common.service;

import com.intel.bkp.bkps.protocol.common.model.RootChainType;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.initialization.service.SigningKeyRepositoryService;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.psgcertificate.PsgCertificateEntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateRootEntryBuilder;
import com.intel.bkp.core.psgcertificate.model.CertificateEntryWrapper;
import com.intel.bkp.core.psgcertificate.model.PsgCertificateType;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static lombok.AccessLevel.PACKAGE;

@Service
@AllArgsConstructor(access = PACKAGE)
@Transactional
@Slf4j
public class BkpsDHCertBuilder {

    private final SigningKeyRepositoryService signingKeyRepositoryService;

    public byte[] getChain(RootChainType rootChainType) {
        return RootChainType.SINGLE == rootChainType ? getChainSingle() : getChainMulti();
    }

    private byte[] getChain(List<CertificateEntryWrapper> certificateChainList) {
        makeRootFirst(certificateChainList);

        List<byte[]> certContentSwapped = getCertContentSwapped(certificateChainList);

        int sum = certContentSwapped.stream().mapToInt(c -> c.length).sum();

        final ByteBuffer byteBuffer = ByteBuffer.allocate(sum);
        certContentSwapped.forEach(byteBuffer::put);
        return byteBuffer.array();
    }

    private byte[] getChainSingle() {
        return getChain(signingKeyRepositoryService.getActiveSigningKeyChain());
    }

    private byte[] getChainMulti() {
        return getChain(signingKeyRepositoryService.getActiveSigningKeyMultiChain());
    }

    private List<byte[]> getCertContentSwapped(List<CertificateEntryWrapper> certificateChainList) {
        final List<byte[]> certificateChainSwapped = new ArrayList<>();

        certificateChainList.forEach(c -> {
            if (PsgCertificateType.ROOT.equals(c.getType())) {
                certificateChainSwapped.add(getRootContentSwapped(c.getContent()));
            } else if (PsgCertificateType.LEAF.equals(c.getType())) {
                certificateChainSwapped.add(getLeafContentSwapped(c.getContent()));
            }
        });
        return certificateChainSwapped;
    }

    private byte[] getRootContentSwapped(byte[] content) {
        try {
            return new PsgCertificateRootEntryBuilder().parse(content)
                .withActor(EndiannessActor.FIRMWARE).build().array();
        } catch (ParseStructureException e) {
            throw new BKPInternalServerException(ErrorCodeMap.PSG_CERTIFICATE_EXCEPTION, e);
        }
    }

    private byte[] getLeafContentSwapped(byte[] content) {
        try {
            return new PsgCertificateEntryBuilder().parse(content)
                .withActor(EndiannessActor.FIRMWARE).build().array();
        } catch (ParseStructureException e) {
            throw new BKPInternalServerException(ErrorCodeMap.PSG_CERTIFICATE_EXCEPTION, e);
        }
    }

    private static void makeRootFirst(List<CertificateEntryWrapper> certificateChainList) {
        if (!PsgCertificateType.ROOT.equals(certificateChainList.get(0).getType())) {
            Collections.reverse(certificateChainList);
        }
    }
}
