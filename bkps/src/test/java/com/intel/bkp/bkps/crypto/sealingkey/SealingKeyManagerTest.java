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

package com.intel.bkp.bkps.crypto.sealingkey;

import com.intel.bkp.bkps.crypto.sealingkey.event.SealingKeyCreationEvent;
import com.intel.bkp.bkps.domain.SealingKey;
import com.intel.bkp.bkps.domain.SealingKey_;
import com.intel.bkp.bkps.domain.enumeration.SealingKeyStatus;
import com.intel.bkp.bkps.repository.SealingKeyRepository;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.initialization.model.dto.SealingKeyResponseDTO;
import com.intel.bkp.bkps.rest.initialization.model.mapper.SealingKeyMapper;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.test.KeyGenUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mapstruct.factory.Mappers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.jpa.domain.Specification;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.test.AssertionUtils.verifyExpectedErrorCode;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class SealingKeyManagerTest {

    private static final String SEALING_KEY_GUID_ACTIVE = "113b441f-3dd1-452c-bed4-7658f01803d1";
    private static final String SEALING_KEY_GUID_PENDING = "7658f018-bed4-452c-3dd1-113b441f0987";

    private final Specification<SealingKey> specSealingKeyActive = (root, query, cb) ->
        cb.equal(root.get(SealingKey_.status), SealingKeyStatus.ENABLED);

    private final Specification<SealingKey> specSealingKeyPending = (root, query, cb) ->
        cb.equal(root.get(SealingKey_.status), SealingKeyStatus.PENDING);

    @Mock
    private SealingKey sealingKeyActive;

    @Mock
    private SealingKey sealingKeyPending;

    @Mock
    private SecretKey mockSecretKey;

    @Mock
    private ISecurityProvider securityService;

    @Mock
    private SealingKeyRepository sealingKeyRepository;

    @Spy
    private SealingKeyMapper sealingKeyMapper = Mappers.getMapper(SealingKeyMapper.class);

    @Mock
    private ApplicationEventPublisher eventPublisher;

    @InjectMocks
    private SealingKeyManager sut;

    @BeforeEach
    void setUp() {
        when(sealingKeyActive.getGuid()).thenReturn(SEALING_KEY_GUID_ACTIVE);
        when(sealingKeyPending.getGuid()).thenReturn(SEALING_KEY_GUID_PENDING);

        when(sealingKeyRepository.findByStatus(SealingKeyStatus.ENABLED)).thenReturn(specSealingKeyActive);
        when(sealingKeyRepository.findByStatus(SealingKeyStatus.PENDING)).thenReturn(specSealingKeyPending);
    }

    @Test
    void rollbackKeyInSecurityService_Success() {
        // given
        String securityObjectId = "test";

        // when
        sut.rollbackKeyInSecurityService(new SealingKeyCreationEvent(securityObjectId));

        // then
        verify(securityService).deleteSecurityObject(securityObjectId);
    }

    @Test
    void create_Success() {
        // given
        mockSealingKeyIsSuccesfullyCreated();

        // when
        sut.createActiveKey();

        // then
        verify(eventPublisher).publishEvent(any(SealingKeyCreationEvent.class));
        verify(securityService).createSecurityObject(any(), anyString());
        verify(sealingKeyRepository).save(any());
    }

    @Test
    void createPendingKey_Success() {
        // given
        mockSealingKeyIsSuccesfullyCreated();

        // when
        sut.createPendingKey();

        // then
        verify(eventPublisher).publishEvent(any(SealingKeyCreationEvent.class));
        verify(securityService).createSecurityObject(any(), anyString());
        verify(sealingKeyRepository).save(any());
    }

    @Test
    void create_FailsToCreateNewKey_Throws() {
        // given
        mockSealingKeyFailedToBeCreated();

        // when-then
        final BKPInternalServerException exception = assertThrows(BKPInternalServerException.class,
            () -> sut.createActiveKey()
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.FAILED_TO_SAVE_SEALING_KEY_IN_SECURITY_ENCLAVE);
    }

    @Test
    void createExportablePendingKey_Success() throws KeystoreGenericException {
        // given
        mockSealingKeyIsSuccesfullyCreated();

        // when
        sut.createExportablePendingKey();

        // then
        verify(eventPublisher).publishEvent(any(SealingKeyCreationEvent.class));
        verify(securityService).importSecretKey(any(), any());
        verify(sealingKeyRepository).save(any());
    }

    @Test
    void importSecretKeyAsPending_Success() throws Exception {
        // given
        mockSealingKeyIsSuccesfullyCreated();
        SecretKey secretKey = KeyGenUtils.genAes256();

        // when
        sut.importSecretKeyAsPending(secretKey);

        // then
        verify(eventPublisher).publishEvent(any(SealingKeyCreationEvent.class));
        verify(securityService).importSecretKey(anyString(), eq(secretKey));
        verify(sealingKeyRepository).save(any());
    }

    @Test
    void getActiveKey_Success() {
        // given
        mockActiveSealingKeyExistsInDb();
        mockActiveSealingKeyExistsInSecurityEnclave();

        // when
        SecretKey result = sut.getActiveKey();

        // then
        assertNotNull(result);
    }

    @Test
    void getPendingKey_Success() {
        // given
        mockPendingSealingKeyExistsInDb();
        mockPendingSealingKeyExistsInSecurityEnclave();

        // when
        SecretKey result = sut.getPendingKey();

        // then
        assertNotNull(result);
    }

    @Test
    void disableActiveKey_Success() {
        // given
        mockActiveSealingKeyExistsInDb();

        // when
        sut.disableActiveKey();

        // then
        verify(sealingKeyActive).setStatus(SealingKeyStatus.DISABLED);
        verify(sealingKeyRepository).save(sealingKeyActive);
    }

    @Test
    void activatePendingKey_Success() {
        // given
        mockPendingSealingKeyExistsInDb();

        // when
        sut.activatePendingKey();

        // then
        verify(sealingKeyPending).setStatus(SealingKeyStatus.ENABLED);
        verify(sealingKeyRepository).save(sealingKeyPending);
    }

    @Test
    void disablePendingKey_Success() {
        // given
        mockPendingSealingKeyExistsInDb();

        // when
        sut.disablePendingKey();

        // then
        verify(sealingKeyPending).setStatus(SealingKeyStatus.DISABLED);
        verify(sealingKeyRepository).save(sealingKeyPending);
    }

    @Test
    void disablePendingKeyAsync_Success() {
        // given
        mockPendingSealingKeyExistsInDb();

        // when
        sut.disablePendingKeyAsync();

        // then
        verify(sealingKeyPending).setStatus(SealingKeyStatus.DISABLED);
        verify(sealingKeyRepository).save(sealingKeyPending);
    }

    @Test
    void list_Success() {
        // given
        int expectedSize = 5;
        mockListOfSealingKeysInRepository(expectedSize);

        // when
        List<SealingKeyResponseDTO> result = sut.list();

        // then
        assertEquals(expectedSize, result.size());
    }

    @Test
    void list_NotSorted_ReturnsSorted() {
        // given
        int expectedSize = 5;
        mockListOfSealingKeysInRepositoryNotSorted(expectedSize);

        // when
        List<SealingKeyResponseDTO> result = sut.list();

        // then
        assertEquals(expectedSize, result.size());
        assertListSortedBySealingKeyId(result);
    }

    @Test
    void isActiveSealingKeyInDatabase_Success() {
        // given
        mockActiveSealingKeyExistsInDb();

        // when
        boolean result = sut.isActiveSealingKeyInDatabase();

        // then
        assertTrue(result);
    }

    @Test
    void isActiveSealingKey_Success() {
        // given
        mockActiveSealingKeyExistsInDb();
        mockActiveSealingKeyExistsInSecurityEnclave();

        // when
        boolean result = sut.isActiveSealingKey();

        // then
        assertTrue(result);
    }

    @Test
    void isPendingSealingKey_Success() {
        // given
        mockPendingSealingKeyExistsInDb();
        mockPendingSealingKeyExistsInSecurityEnclave();

        // when
        boolean result = sut.isPendingSealingKey();

        // then
        assertTrue(result);
    }

    @Test
    void isActiveSealingKey_ExistsInDbNotEnclave_Throws() {
        // given
        mockActiveSealingKeyExistsInDb();
        mockActiveSealingKeyDoesNotExistInSecurityEnclave();

        // when-then
        final BKPInternalServerException exception = assertThrows(BKPInternalServerException.class,
            () -> sut.isActiveSealingKey()
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.SEALING_KEY_EXISTS_IN_DB_BUT_NOT_ENCLAVE);
    }

    @Test
    void isPendingSealingKey_ExistsInDbAndEnclave_Success() {
        // given
        mockPendingSealingKeyExistsInDb();
        mockPendingSealingKeyExistsInSecurityEnclave();

        // when
        boolean result = sut.isPendingSealingKey();

        // then
        assertTrue(result);
    }

    @Test
    void isActiveSealingKey_DoesNotExistInDb_Success() {
        // given
        mockActiveSealingKeyDoesNotExistInDb();

        // when
        boolean result = sut.isActiveSealingKey();

        // then
        assertFalse(result);
    }

    @Test
    void getSecretKey_KeyDoesNotExist_Throws() {
        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.getSecretKey(Optional.empty())
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.SEALING_KEY_DOES_NOT_EXIST);
    }

    @Test
    void isKeyPresent_ExistsInDbAndEnclave_Success() {
        // given
        mockActiveSealingKeyExistsInDb();
        mockActiveSealingKeyExistsInSecurityEnclave();

        // when
        boolean result = sut.isKeyPresent(Optional.of(sealingKeyActive));

        // then
        assertTrue(result);
    }

    @Test
    void isKeyPresent_DoesNotExist_Success() {
        // when
        boolean result = sut.isKeyPresent(Optional.empty());

        // then
        assertFalse(result);
    }

    @Test
    void isKeyPresent_ExistsInDbNotEnclave_Throws() {
        // given
        mockActiveSealingKeyExistsInDb();
        mockActiveSealingKeyDoesNotExistInSecurityEnclave();

        // when-then
        final BKPInternalServerException exception = assertThrows(BKPInternalServerException.class,
            () -> sut.isKeyPresent(Optional.of(sealingKeyActive))
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.SEALING_KEY_EXISTS_IN_DB_BUT_NOT_ENCLAVE);
    }

    private void mockActiveSealingKeyExistsInDb() {
        when(sealingKeyRepository.findOne(specSealingKeyActive)).thenReturn(Optional.of(sealingKeyActive));
    }

    private void mockActiveSealingKeyDoesNotExistInDb() {
        when(sealingKeyRepository.findOne(specSealingKeyActive)).thenReturn(Optional.empty());
    }

    private void mockActiveSealingKeyExistsInSecurityEnclave() {
        when(securityService.existsSecurityObject(sealingKeyActive.getGuid())).thenReturn(true);
        when(securityService.getKeyFromSecurityObject(sealingKeyActive.getGuid())).thenReturn(mockSecretKey);
    }

    private void mockActiveSealingKeyDoesNotExistInSecurityEnclave() {
        when(securityService.existsSecurityObject(sealingKeyActive.getGuid())).thenReturn(false);
    }

    private void mockPendingSealingKeyExistsInDb() {
        when(sealingKeyRepository.findOne(specSealingKeyPending)).thenReturn(Optional.of(sealingKeyPending));
    }

    private void mockPendingSealingKeyExistsInSecurityEnclave() {
        when(securityService.existsSecurityObject(sealingKeyPending.getGuid())).thenReturn(true);
        when(securityService.getKeyFromSecurityObject(sealingKeyPending.getGuid())).thenReturn(mockSecretKey);
    }

    private void mockSealingKeyIsSuccesfullyCreated() {
        mockSecurityObject(true);
    }

    private void mockSealingKeyFailedToBeCreated() {
        mockSecurityObject(false);
    }

    private void mockSecurityObject(boolean exists) {
        when(securityService.existsSecurityObject(anyString())).thenReturn(exists);
    }

    private void mockListOfSealingKeysInRepository(int expectedSize) {
        ArrayList<SealingKey> sealingKeys = mockListOfSealingKeys(expectedSize);
        mockSealingKeyRepositoryReturnsSealingKeys(sealingKeys);
    }

    private void mockListOfSealingKeysInRepositoryNotSorted(int expectedSize) {
        ArrayList<SealingKey> sealingKeys = mockListOfSealingKeys(expectedSize);
        Collections.reverse(sealingKeys);
        mockSealingKeyRepositoryReturnsSealingKeys(sealingKeys);
    }

    private ArrayList<SealingKey> mockListOfSealingKeys(int expectedSize) {
        ArrayList<SealingKey> sealingKeys = new ArrayList<>(expectedSize);
        for (int i = 0; i < expectedSize; i++) {
            SealingKey entity = new SealingKey();
            entity.id((long) i);
            entity.status(SealingKeyStatus.ENABLED);
            sealingKeys.add(entity);
        }
        return sealingKeys;
    }

    private void mockSealingKeyRepositoryReturnsSealingKeys(ArrayList<SealingKey> sealingKeys) {
        when(sealingKeyRepository.findAll()).thenReturn(sealingKeys);
    }

    private void assertListSortedBySealingKeyId(List<SealingKeyResponseDTO> result) {
        for (int i = 0; i < result.size() - 1; i++) {
            assertTrue(result.get(i).getSealingKeyId() < result.get(i + 1).getSealingKeyId());
        }
    }
}
