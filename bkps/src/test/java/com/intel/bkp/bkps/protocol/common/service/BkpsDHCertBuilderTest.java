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
import com.intel.bkp.bkps.rest.initialization.service.SigningKeyRepositoryService;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.core.psgcertificate.PsgCertificateEntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateRootEntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgPublicKeyBuilder;
import com.intel.bkp.core.psgcertificate.PsgSignatureBuilder;
import com.intel.bkp.core.psgcertificate.model.CertificateEntryWrapper;
import com.intel.bkp.core.psgcertificate.model.PsgCertificateType;
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.test.KeyGenUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PublicKey;
import java.util.Collections;

import static com.intel.bkp.test.AssertionUtils.assertThatArrayIsSubarrayOfAnotherArray;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class BkpsDHCertBuilderTest {

    private static final PublicKey PUB_KEY = KeyGenUtils.genEc256().getPublic();

    @Mock
    private SigningKeyRepositoryService signingKeyRepositoryService;

    @InjectMocks
    private BkpsDHCertBuilder sut;

    private final PsgPublicKeyBuilder psgPublicKeyBuilder = new PsgPublicKeyBuilder()
        .publicKey(PUB_KEY, PsgCurveType.SECP256R1);
    private final PsgSignatureBuilder psgSignatureBuilder = PsgSignatureBuilder
        .empty(PsgSignatureCurveType.SECP384R1);

    @Test
    void getChain_SingleChain_Success() {
        // given
        byte[] certificateInBkpsFormat = prepareCertificate();
        byte[] expectedCertInFwFormat = prepareCertificateInFwFormat();

        when(signingKeyRepositoryService.getActiveSigningKeyChain()).thenReturn(Collections.singletonList(
            new CertificateEntryWrapper(PsgCertificateType.LEAF, certificateInBkpsFormat)));

        // when
        byte[] certChain = sut.getChain(RootChainType.SINGLE);

        // then
        assertTrue(certChain.length > 0);
        assertThatArrayIsSubarrayOfAnotherArray(certChain, expectedCertInFwFormat);
    }

    @Test
    void getChain_SingleChain_WithInvalidCertificateProvided_Throws() {
        // given
        byte[] certificateInBkpsFormat = prepareMultiRootCertificate();

        when(signingKeyRepositoryService.getActiveSigningKeyChain()).thenReturn(Collections.singletonList(
            new CertificateEntryWrapper(PsgCertificateType.LEAF, certificateInBkpsFormat)));

        // when-then
        assertThrows(BKPInternalServerException.class, () -> sut.getChain(RootChainType.SINGLE));
    }

    @Test
    void getChain_MultiChain_Success() {
        // given
        byte[] certificateInBkpsFormat = prepareMultiRootCertificate();
        byte[] expectedCertInFwFormat = prepareMultiRootCertificateInFwFormat();

        when(signingKeyRepositoryService.getActiveSigningKeyMultiChain()).thenReturn(Collections.singletonList(
            new CertificateEntryWrapper(PsgCertificateType.ROOT, certificateInBkpsFormat)));

        // when
        byte[] certChain = sut.getChain(RootChainType.MULTI);

        // then
        assertTrue(certChain.length > 0);
        assertThatArrayIsSubarrayOfAnotherArray(certChain, expectedCertInFwFormat);
    }

    @Test
    void getChain_MultiChain_WithInvalidCertificateProvided_Throws() {
        // given
        byte[] certificateInBkpsFormat = prepareCertificate();

        when(signingKeyRepositoryService.getActiveSigningKeyMultiChain()).thenReturn(Collections.singletonList(
            new CertificateEntryWrapper(PsgCertificateType.ROOT, certificateInBkpsFormat)));

        // when-then
        assertThrows(BKPInternalServerException.class, () -> sut.getChain(RootChainType.MULTI));
    }

    private byte[] prepareCertificate() {
        return new PsgCertificateEntryBuilder()
            .publicKey(psgPublicKeyBuilder)
            .withSignature(psgSignatureBuilder)
            .build()
            .array();
    }

    private byte[] prepareCertificateInFwFormat() {
        return new PsgCertificateEntryBuilder()
            .publicKey(psgPublicKeyBuilder)
            .withSignature(psgSignatureBuilder)
            .withActor(EndiannessActor.FIRMWARE)
            .build()
            .array();
    }

    private byte[] prepareMultiRootCertificate() {
        return new PsgCertificateRootEntryBuilder()
            .publicKey(psgPublicKeyBuilder)
            .build()
            .array();
    }

    private byte[] prepareMultiRootCertificateInFwFormat() {
        return new PsgCertificateRootEntryBuilder()
            .publicKey(psgPublicKeyBuilder)
            .withActor(EndiannessActor.FIRMWARE)
            .build()
            .array();
    }
}
