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

package com.intel.bkp.bkps.rest.initialization.service;

import com.intel.bkp.bkps.domain.CustomerRootSigningKey;
import com.intel.bkp.bkps.exception.RootSigningKeyNotExistException;
import com.intel.bkp.bkps.repository.RootSigningKeyRepository;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.util.PsgCertificateManager;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.psgcertificate.PsgCertificateEntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateRootEntry;
import com.intel.bkp.core.psgcertificate.PsgCertificateRootEntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgPublicKeyBuilder;
import com.intel.bkp.core.psgcertificate.PsgSignatureBuilder;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateChainWrongSizeException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidRootCertificateException;
import com.intel.bkp.core.psgcertificate.model.CertificateEntryWrapper;
import com.intel.bkp.core.psgcertificate.model.PsgCertificateType;
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKey;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKeyMagic;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.test.KeyGenUtils;
import com.intel.bkp.test.SigningUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.AdditionalMatchers;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.jpa.domain.Specification;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.test.AssertionUtils.verifyExpectedErrorCode;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class SigningKeyServiceTest {


    private static final String SINGLE_CHAIN = "01020304";
    private static final String MULTI_CHAIN = "05060708";
    private static final long SIGNING_KEY_ID = 1L;

    @Mock
    private SigningKeyRepositoryService signingKeyRepositoryService;

    @Mock
    private PsgCertificateManager certificateManager;

    @Mock
    private RootSigningKeyRepository rootSigningKeyRepository;

    @Mock
    private CustomerRootSigningKey customerRootSigningKey;

    @Mock
    private PsgCertificateRootEntryBuilder psgCertificateRootEntryBuilder;

    @Mock
    private PsgCertificateRootEntry psgCertificateRootEntry;

    @Mock
    private PsgPublicKeyBuilder psgPublicKeyBuilder;

    @Mock
    private PsgPublicKey psgPublicKey;

    @InjectMocks
    private SigningKeyService sut;

    @BeforeEach
    void setUp() {
        sut.setCertificateManager(certificateManager);
        when(psgCertificateRootEntryBuilder.getPsgPublicKeyBuilder()).thenReturn(psgPublicKeyBuilder);
        when(psgCertificateRootEntryBuilder.build()).thenReturn(psgCertificateRootEntry);
        when(psgPublicKeyBuilder.build()).thenReturn(psgPublicKey);
        when(psgPublicKey.getPointX()).thenReturn(new byte[1]);
        when(psgPublicKey.getPointY()).thenReturn(new byte[1]);
    }

    private SigningKeyService mockCertificateEndiannessConversion(String chainToParse) {
        LinkedList<CertificateEntryWrapper> mockList = new LinkedList<>();
        mockList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, chainToParse.getBytes()));

        SigningKeyService spy = spy(sut);
        doReturn(mockList).when(spy).convertEndiannessInCertificateChain(chainToParse);
        return spy;
    }

    private SigningKeyService mockCertificateEndiannessConversion(
        LinkedList<CertificateEntryWrapper> mockedListToReturn) {

        SigningKeyService spy = spy(sut);
        doReturn(mockedListToReturn, mockedListToReturn)
            .when(spy)
            .convertEndiannessInCertificateChain(AdditionalMatchers.or(eq(SINGLE_CHAIN), eq(MULTI_CHAIN)));
        return spy;
    }

    private byte[] prepareLeafPsgCertificate() {
        KeyPair keyPair = KeyGenUtils.genEc384();
        assert keyPair != null;

        PsgPublicKeyBuilder psgPublicKeyBuilder = getPsgPublicKeyBuilder(keyPair, PsgCurveType.SECP384R1);
        PsgSignatureBuilder psgSignatureBuilder = getPsgSignatureBuilder(PsgSignatureCurveType.SECP384R1);

        return new PsgCertificateEntryBuilder()
            .publicKey(psgPublicKeyBuilder)
            .withSignature(psgSignatureBuilder)
            .signData(dataToSign -> SigningUtils.signEcData(
                dataToSign, keyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA
            ), PsgSignatureCurveType.SECP384R1)
            .withActor(EndiannessActor.FIRMWARE)
            .build()
            .array();
    }

    private PsgPublicKeyBuilder getPsgPublicKeyBuilder(KeyPair keyPair, PsgCurveType psgCurveType) {
        return new PsgPublicKeyBuilder()
            .magic(PsgPublicKeyMagic.M1_MAGIC)
            .publicKey(keyPair.getPublic(), psgCurveType);
    }

    private PsgSignatureBuilder getPsgSignatureBuilder(PsgSignatureCurveType psgSignatureCurveType) {
        return PsgSignatureBuilder.empty(psgSignatureCurveType);
    }

    @Test
    void convertEndiannessInCertificateChain_WithEmptyChain_Throws() {
        // given
        String preparedChain = toHex("DummyChain".getBytes(StandardCharsets.UTF_8));

        // when-then
        assertThrows(BKPBadRequestException.class,
            () -> sut.convertEndiannessInCertificateChain(preparedChain));
    }

    @Test
    void convertEndiannessInCertificateChain_Success() {
        // given
        String preparedChain = toHex(prepareLeafPsgCertificate());

        // when
        final List<CertificateEntryWrapper> result =
            sut.convertEndiannessInCertificateChain(preparedChain);

        // then
        assertEquals(1, result.size());
    }

    @Test
    void addRootSigningPublicKey_Success() throws Exception {
        // given
        when(certificateManager.findRootCertificateInChain(any())).thenReturn(psgCertificateRootEntryBuilder);
        when(rootSigningKeyRepository.existsByCertificateHash(anyString())).thenReturn(false);
        mockPubKey();
        String pubKey = """
            iSWQNgAAAJoAAACCAAAAAAAAAAAAAAAAAAAAAAAAAACTEFEYAAAAMQAAADFUMmZIAAAAAAAAAAAA
            SmY+Ly08jWZtc2u/AFUyrpSKQEWuA0jdRoZxl1YKLoRT+zHs6U/DvCg7RJ/EXMOWAM3xlLlu4v9i
            0Usk1jz0akqrCQWHpzl+ilaK/2A+ELCsyYfi6/JdTndY/OzxGu7Puw==""";

        SigningKeyService spy = mockCertificateEndiannessConversion(pubKey);

        // when
        spy.addRootSigningPublicKey(pubKey);

        // then
        verify(certificateManager).findRootCertificateInChain(any());
        verify(rootSigningKeyRepository).existsByCertificateHash(anyString());
        verify(rootSigningKeyRepository).save(any(CustomerRootSigningKey.class));
    }

    @Test
    void addRootSigningPublicKey_WithNotParsableCertificate_ThrowsException()
        throws PsgInvalidRootCertificateException, PsgCertificateChainWrongSizeException {
        // given
        String pubKey = "test";
        SigningKeyService spy = mockCertificateEndiannessConversion(pubKey);
        when(certificateManager.findRootCertificateInChain(any())).thenThrow(PsgInvalidRootCertificateException.class);

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> spy.addRootSigningPublicKey(pubKey)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.FAILED_TO_PARSE_ROOT_PUBLIC_KEY);
    }

    @Test
    void addRootSigningPublicKey_WithExistingFingerprint_ThrowsException()
        throws PsgInvalidRootCertificateException, PsgCertificateChainWrongSizeException {
        // given
        when(certificateManager.findRootCertificateInChain(any())).thenReturn(psgCertificateRootEntryBuilder);
        when(rootSigningKeyRepository.existsByCertificateHash(anyString())).thenReturn(true);
        mockPubKey();
        String pubKey = "test";

        SigningKeyService spy = mockCertificateEndiannessConversion(pubKey);

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> spy.addRootSigningPublicKey(pubKey)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.ROOT_SIGNING_KEY_ALREADY_EXISTS);
    }

    @Test
    void uploadSigningKeyChain_Success() throws Exception {
        // given
        LinkedList<CertificateEntryWrapper> certificateEntryWrappers = new LinkedList<>();
        certificateEntryWrappers.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));
        certificateEntryWrappers.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, new byte[4]));
        when(certificateManager.findRootCertificateInChain(any())).thenReturn(psgCertificateRootEntryBuilder);
        when(rootSigningKeyRepository.findOne(ArgumentMatchers.<Specification<CustomerRootSigningKey>>any()))
            .thenReturn(Optional.of(customerRootSigningKey));
        mockPubKey();

        SigningKeyService spy = mockCertificateEndiannessConversion(certificateEntryWrappers);

        // when
        spy.uploadSigningKeyChain(SIGNING_KEY_ID, SINGLE_CHAIN, MULTI_CHAIN);

        // then
        verify(certificateManager, times(2)).verifyLeafCertificatePermissions(any());
        verify(certificateManager, times(2)).verifyRootCertificate(any(), any());
        verify(certificateManager, times(2)).verifyParentsInChainByPubKey(any());

        verify(signingKeyRepositoryService).addChainToSigningKey(anyLong(), any(), any());
    }

    @Test
    void uploadSigningKeyChain_WithMissingRootSigningKeyFingerprint_ThrowsException()
        throws PsgCertificateChainWrongSizeException, PsgInvalidRootCertificateException {
        // given
        LinkedList<CertificateEntryWrapper> certificateEntryWrappers = new LinkedList<>();
        certificateEntryWrappers.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));
        certificateEntryWrappers.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, new byte[4]));
        when(certificateManager.findRootCertificateInChain(any())).thenReturn(
            psgCertificateRootEntryBuilder);
        when(rootSigningKeyRepository.findOne(ArgumentMatchers.<Specification<CustomerRootSigningKey>>any()))
            .thenReturn(Optional.empty());
        mockPubKey();

        SigningKeyService spy = mockCertificateEndiannessConversion(certificateEntryWrappers);

        // when
        assertThrows(RootSigningKeyNotExistException.class,
            () -> spy.uploadSigningKeyChain(SIGNING_KEY_ID, SINGLE_CHAIN, MULTI_CHAIN));
    }

    @Test
    void uploadSigningKeyChain_WithWrongCertificateSizeInSecondMethod_ThrowsException()
        throws PsgCertificateChainWrongSizeException, PsgInvalidRootCertificateException {
        // given
        LinkedList<CertificateEntryWrapper> certificateEntryWrappers = new LinkedList<>();
        certificateEntryWrappers.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));
        certificateEntryWrappers.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, new byte[4]));
        when(certificateManager.findRootCertificateInChain(certificateEntryWrappers))
            .thenThrow(PsgCertificateChainWrongSizeException.class);

        SigningKeyService spy =
            mockCertificateEndiannessConversion(certificateEntryWrappers);

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> spy.uploadSigningKeyChain(SIGNING_KEY_ID, SINGLE_CHAIN, MULTI_CHAIN));

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.CERTIFICATE_CHAIN_WRONG_SIZE);
    }

    @Test
    void uploadSigningKeyChain_WithWrongRootCertificate_ThrowsException()
        throws PsgCertificateChainWrongSizeException, PsgInvalidRootCertificateException {
        // given
        LinkedList<CertificateEntryWrapper> certificateEntryWrappers = new LinkedList<>();
        certificateEntryWrappers.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));
        certificateEntryWrappers.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));
        when(certificateManager.findRootCertificateInChain(certificateEntryWrappers))
            .thenThrow(PsgInvalidRootCertificateException.class);

        SigningKeyService spy =
            mockCertificateEndiannessConversion(certificateEntryWrappers);

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> spy.uploadSigningKeyChain(SIGNING_KEY_ID, SINGLE_CHAIN, MULTI_CHAIN));

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.CERTIFICATE_CHAIN_VALIDATION_FAILED);
    }

    @Test
    void createSigningKey_Success() {
        //when
        sut.createSigningKey();

        // then
        verify(signingKeyRepositoryService).createSigningKey();
    }

    @Test
    void getSigningKeyPublicPart_WithValidId_InvokesProperCommand() {
        // given
        long signingKeyId = 1L;

        //when
        sut.getSigningKeyPublicPart(signingKeyId);

        // then
        verify(signingKeyRepositoryService).getSigningKeyPublicPartPem(signingKeyId);
    }

    @Test
    void getAllSigningKeys_Success() {
        //when
        sut.getAllSigningKeys();

        // then
        verify(signingKeyRepositoryService).getList();
    }

    @Test
    void activateSigningKey_Success() {
        // given
        long signingKeyId = 1L;

        //when
        sut.activateSigningKey(signingKeyId);

        // then
        verify(signingKeyRepositoryService).activate(signingKeyId);
    }

    private void mockPubKey() {
        final ECPublicKey publicKey = (ECPublicKey) KeyGenUtils.genEc384().getPublic();
        when(signingKeyRepositoryService.getSigningKeyPublicPart(1L)).thenReturn(publicKey);
        when(psgCertificateRootEntryBuilder.getPsgPublicKeyBuilder())
            .thenReturn(new PsgPublicKeyBuilder().publicKey(publicKey, PsgCurveType.SECP384R1));
    }
}
