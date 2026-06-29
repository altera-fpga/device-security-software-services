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

import com.intel.bkp.bkps.domain.SigningKeyCertificate;
import com.intel.bkp.bkps.domain.SigningKeyEntity;
import com.intel.bkp.bkps.domain.SigningKeyMultiCertificate;
import com.intel.bkp.bkps.domain.enumeration.SigningKeyStatus;
import com.intel.bkp.bkps.exception.KeystoreCommonException;
import com.intel.bkp.bkps.exception.SigningKeyCertificateNotExistException;
import com.intel.bkp.bkps.exception.SigningKeyNotExistException;
import com.intel.bkp.bkps.repository.SigningKeyRepository;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.initialization.model.dto.SigningKeyResponseDTO;
import com.intel.bkp.bkps.rest.initialization.model.mapper.SigningKeyMapper;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.core.psgcertificate.model.CertificateEntryWrapper;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.crypto.pem.PemFormatHeader;
import com.intel.bkp.test.KeyGenUtils;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.jpa.domain.Specification;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.core.psgcertificate.model.PsgCertificateType.ROOT;
import static com.intel.bkp.test.AssertionUtils.verifyExpectedErrorCode;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class SigningKeyRepositoryServiceTest {

    @Mock
    private ISecurityProvider securityService;

    @Mock
    private SigningKeyRepository signingKeyRepository;

    @Mock
    private SigningKeyMapper signingKeyMapper;

    @Mock
    private SigningKeyEntity signingKeyEntity;

    @InjectMocks
    private SigningKeyRepositoryService sut;

    private static final Long SIGNING_KEY_ID = 1L;

    @Test
    void createSigningKey_Success() {
        // given
        when(securityService.createSecurityObject(any(), anyString())).thenReturn(KeyGenUtils.genEc256());

        // when
        sut.createSigningKey();

        // then
        verify(securityService).createSecurityObject(any(), anyString());
        verify(signingKeyRepository).save(any(SigningKeyEntity.class));
        verify(signingKeyMapper).toDto(any(SigningKeyEntity.class));
    }

    @Test
    void createSigningKey_WithFailToSaveInSecureEnclave_ThrowsException() {
        // given
        when(securityService.createSecurityObject(any(), anyString())).thenThrow(KeystoreCommonException.class);

        // when
        assertThrows(KeystoreCommonException.class, () -> sut.createSigningKey());
    }

    @Test
    void getSigningKey_Success() {
        // given
        prepareSigningKeyMocks(true, true);

        // when
        SigningKeyEntity signingKey = sut.getSigningKey(SIGNING_KEY_ID);

        // then
        assertEquals(signingKeyEntity, signingKey);
    }

    @Test
    void getSigningKey_WithNotExistingIdInDatabase_ThrowsException() {
        // given
        prepareSigningKeyMocks(true, false);

        // when
        assertThrows(SigningKeyNotExistException.class, () -> sut.getSigningKey(SIGNING_KEY_ID));
    }

    @Test
    void getSigningKey_WithNotExistingIdInSecurityProvider_ThrowsException() {
        // given
        prepareSigningKeyMocks(false, true);

        // when
        assertThrows(SigningKeyNotExistException.class, () -> sut.getSigningKey(SIGNING_KEY_ID));
    }

    @Test
    void getActiveSigningKey_WithNoChain_ThrowsException() {
        // given
        mockActiveSigningKey(true);

        // when
        assertThrows(SigningKeyCertificateNotExistException.class, () -> sut.getActiveSigningKey());
    }

    @Test
    void getActiveSigningKey_Success() {
        // given
        mockActiveSigningKey(true);
        when(signingKeyEntity.getChain()).thenReturn(List.of(new SigningKeyCertificate()));
        when(signingKeyEntity.getMultiChain()).thenReturn(List.of(new SigningKeyMultiCertificate()));

        // when
        final SigningKeyEntity activeSigningKey = sut.getActiveSigningKey();

        // then
        assertEquals(signingKeyEntity, activeSigningKey);
    }

    @Test
    void getActiveSigningKey_WithNotExistingActiveInDatabase_ThrowsException() {
        // given
        when(signingKeyRepository.findOne(ArgumentMatchers.<Specification<SigningKeyEntity>>any()))
            .thenReturn(Optional.empty());

        // when
        assertThrows(SigningKeyNotExistException.class, () -> sut.getActiveSigningKey());

    }

    @Test
    void getActiveSigningKey_WithNotExistingActiveInSecurityProvider_ThrowsException() {
        // given
        mockActiveSigningKey(false);

        // when
        assertThrows(SigningKeyNotExistException.class, () -> sut.getActiveSigningKey());
    }

    @Test
    void getSigningKeyPublicPartPem_Success() {
        // given
        prepareSigningKeyMocks(true, true);
        KeyPair key = KeyGenUtils.genEc256();
        final byte[] publicKey = key.getPublic().getEncoded();
        when(securityService.getPubKeyFromSecurityObject(any())).thenReturn(publicKey);

        // when
        String encodedKey = sut.getSigningKeyPublicPartPem(SIGNING_KEY_ID);

        // then
        assertThat(encodedKey, CoreMatchers.containsString(PemFormatHeader.PUBLIC_KEY.getBegin()));
        assertThat(encodedKey, CoreMatchers.containsString(PemFormatHeader.PUBLIC_KEY.getEnd()));
        verify(securityService).existsSecurityObject(anyString());
        verify(securityService).getPubKeyFromSecurityObject(anyString());
    }

    @Test
    void getSigningKeyPublicPart_ThrowsExceptionDueToKeyIsEmpty() {
        // given
        prepareSigningKeyMocks(true, true);
        final byte[] publicKey = new byte[0];
        when(securityService.existsSecurityObject(any())).thenReturn(true);
        when(securityService.getPubKeyFromSecurityObject(any())).thenReturn(publicKey);
        long signingKeyId = 1L;

        // when
        assertThrows(BKPInternalServerException.class, () -> sut.getSigningKeyPublicPartPem(signingKeyId));
    }

    @Test
    void getList_Success() {
        // given
        final LinkedList<SigningKeyEntity> entities = new LinkedList<>();
        entities.add(new SigningKeyEntity());
        when(signingKeyRepository.findAll()).thenReturn(entities);

        // when
        final List<SigningKeyResponseDTO> list = sut.getList();

        // then
        assertEquals(1, list.size());
    }

    @Test
    void activate_Success() {
        // given
        prepareSigningKeyMocks(true, true);
        when(signingKeyEntity.getStatus()).thenReturn(SigningKeyStatus.DISABLED);

        prepareChain();
        prepareMultiChain();

        // when
        sut.activate(SIGNING_KEY_ID);

        // then
        verify(signingKeyRepository).save(ArgumentMatchers.any(SigningKeyEntity.class));
    }

    @Test
    void activate_WithEnabledSigningKey_MarksDisabledCurrentSigningKeys() {
        // given
        prepareSigningKeyMocks(true, true);
        when(signingKeyEntity.getStatus()).thenReturn(SigningKeyStatus.DISABLED);

        prepareChain();
        prepareMultiChain();

        List<SigningKeyEntity> list = new LinkedList<>();
        final SigningKeyEntity signingKeyEntity = new SigningKeyEntity();
        signingKeyEntity.setId(1L);
        signingKeyEntity.setStatus(SigningKeyStatus.ENABLED);
        list.add(signingKeyEntity);
        when(signingKeyRepository.findAll(ArgumentMatchers.<Specification<SigningKeyEntity>>any())).thenReturn(list);

        // when
        sut.activate(SIGNING_KEY_ID);

        // then
        verify(signingKeyRepository, times(2)).save(ArgumentMatchers.any(SigningKeyEntity.class));
    }

    @Test
    void activate_WithActivatedStatus_ThrowsException() {
        // given
        prepareSigningKeyMocks(true, true);
        when(signingKeyEntity.getStatus()).thenReturn(SigningKeyStatus.ENABLED);

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.activate(SIGNING_KEY_ID)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.SIGNING_KEY_ALREADY_ACTIVATED);
    }

    @Test
    void activate_WithEmptyChain_ThrowsException() {
        // given
        prepareSigningKeyMocks(true, true);
        when(signingKeyEntity.getStatus()).thenReturn(SigningKeyStatus.DISABLED);

        prepareEmptyChain();

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.activate(SIGNING_KEY_ID)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.SIGNING_KEY_IS_NOT_CONFIGURED_MISSING_CHAIN);
    }

    @Test
    void addChainToSigningKey_Success() {
        // given
        prepareSigningKeyMocks(true, true);
        final LinkedList<CertificateEntryWrapper> certificates = new LinkedList<>();
        certificates.add(new CertificateEntryWrapper(ROOT, new byte[4]));

        prepareEmptyChain();
        prepareEmptyMultiChain();

        // when
        sut.addChainToSigningKey(SIGNING_KEY_ID, certificates, certificates);

        // then
        verify(signingKeyRepository).save(ArgumentMatchers.any(SigningKeyEntity.class));
    }

    @Test
    void addChainToSigningKey_WithAlreadyExistingChain_ThrowsException() {
        // given
        prepareSigningKeyMocks(true, true);
        final LinkedList<CertificateEntryWrapper> certificates = new LinkedList<>();
        certificates.add(new CertificateEntryWrapper(ROOT, new byte[4]));

        prepareChain();
        prepareMultiChain();

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.addChainToSigningKey(SIGNING_KEY_ID, certificates, certificates)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.SIGNING_KEY_CHAIN_ALREADY_EXISTS);
    }

    @Test
    void getActiveSigningKeyChain_Success() {
        // given
        mockActiveSigningKey(true);

        prepareChain();
        prepareMultiChain();

        // when
        final List<CertificateEntryWrapper> activeSigningKeyChain = sut.getActiveSigningKeyChain();

        // then
        assertEquals(1, activeSigningKeyChain.size());
    }

    @Test
    void getActiveSigningKeyMultiChain_Success() {
        // given
        mockActiveSigningKey(true);

        prepareChain();
        prepareMultiChain();

        // when
        final List<CertificateEntryWrapper> activeSigningKeyChain = sut.getActiveSigningKeyMultiChain();

        // then
        assertEquals(1, activeSigningKeyChain.size());
    }

    private void mockActiveSigningKey(boolean existsInSecurityEnclave) {
        when(signingKeyRepository.findOne(ArgumentMatchers.<Specification<SigningKeyEntity>>any()))
            .thenReturn(Optional.of(signingKeyEntity));
        when(signingKeyEntity.getName()).thenReturn("test");
        when(securityService.existsSecurityObject(anyString())).thenReturn(existsInSecurityEnclave);
    }

    private void prepareChain() {
        when(signingKeyEntity.getChain()).thenReturn(List.of(new SigningKeyCertificate(ROOT, new byte[4])));
    }

    private void prepareMultiChain() {
        when(signingKeyEntity.getMultiChain()).thenReturn(List.of(new SigningKeyMultiCertificate(ROOT, new byte[3])));
    }

    private void prepareEmptyChain() {
        when(signingKeyEntity.getChain()).thenReturn(new ArrayList<>());
    }

    private void prepareEmptyMultiChain() {
        when(signingKeyEntity.getMultiChain()).thenReturn(new ArrayList<>());
    }

    private void prepareSigningKeyMocks(boolean securityObjExists, boolean mockIfExistsInDb) {
        when(securityService.existsSecurityObject(anyString())).thenReturn(securityObjExists);

        if (mockIfExistsInDb) {
            when(signingKeyEntity.getName()).thenReturn("test");
            when(signingKeyRepository.findById(ArgumentMatchers.anyLong())).thenReturn(Optional.of(signingKeyEntity));
        }
    }
}
