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

package com.intel.bkp.bkps.rest.configuration.service;

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmSealingKeyProviderImpl;
import com.intel.bkp.bkps.crypto.sealingkey.SealingKeyManager;
import com.intel.bkp.bkps.domain.AppraisalPolicy;
import com.intel.bkp.bkps.exception.AppraisalPolicyNotFound;
import com.intel.bkp.bkps.repository.AppraisalPolicyRepository;
import com.intel.bkp.bkps.rest.configuration.model.dto.AppraisalPolicyDTO;
import com.intel.bkp.bkps.rest.configuration.model.dto.AppraisalPolicyResponseDTO;
import com.intel.bkp.bkps.rest.configuration.model.mapper.AppraisalPolicyMapper;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.test.FileUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.test.AssertionUtils.verifyExpectedErrorCode;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class AppraisalPolicyServiceTest {

    private String appraisalPolicyContent = "mocked data";
    private byte[] encryptedContentHex = fromHex("aabbccdd");
    private String TEST_FOLDER = "testdata";

    @Mock
    private AppraisalPolicyRepository appraisalPolicyRepository;

    @Mock
    private AppraisalPolicyMapper appraisalPolicyMapper;

    @Mock
    private AesGcmSealingKeyProviderImpl aesGcmSealingKeyProvider;

    @Mock
    private SealingKeyManager sealingKeyManager;

    @Mock
    private AppraisalPolicy appraisalPolicy;

    @Mock
    private AppraisalPolicy encryptedAppraisalPolicy;

    @Mock
    private AppraisalPolicyDTO appraisalPolicyDTO;

    @Mock
    private AppraisalPolicyResponseDTO appraisalPolicyResponseDTO;

    @InjectMocks
    private AppraisalPolicyService sut;

    @BeforeEach
    void setUp() throws Exception {
        when(appraisalPolicy.getId()).thenReturn(1L);
        appraisalPolicyContent = FileUtils.readFromResourcesAsString(TEST_FOLDER, "test_appraisal_policy.txt");
        when(appraisalPolicy.getContent()).thenReturn(appraisalPolicyContent);
        when(aesGcmSealingKeyProvider.encrypt(any())).thenReturn(encryptedContentHex);
        when(appraisalPolicyMapper.toEntity(appraisalPolicyDTO)).thenReturn(appraisalPolicy);
        when(appraisalPolicyRepository.save(any())).thenReturn(appraisalPolicy);
        when(appraisalPolicyMapper.toDto(appraisalPolicy)).thenReturn(appraisalPolicyDTO);
        when(appraisalPolicyMapper.toResultDto(appraisalPolicy)).thenReturn(appraisalPolicyResponseDTO);
        mockPendingSealingKeyDoesNotExist();
        mockActiveSealingKeyExists();
    }

    @Test
    void save_CallsSave() throws EncryptionProviderException {
        // when
        final var result = sut.save(appraisalPolicyDTO);

        // then
        verify(aesGcmSealingKeyProvider).encrypt(appraisalPolicyContent.getBytes(StandardCharsets.UTF_8));
        verify(appraisalPolicy).setContent(toHex(encryptedContentHex));
        verify(appraisalPolicyRepository).save(appraisalPolicy);
        assertEquals(appraisalPolicyResponseDTO, result);
    }

    @Test
    void save_SealingKeyRotationPending_Throws() {
        // given
        mockPendingSealingKeyExists();

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.save(appraisalPolicyDTO)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.SEALING_KEY_ROTATION_PENDING);
    }

    @Test
    void save_NoActiveSealingKey_Throws() {
        // given
        mockActiveSealingKeyDoesNotExist();

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.save(appraisalPolicyDTO)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.ACTIVE_SEALING_KEY_DOES_NOT_EXIST);
    }

    @Test
    void save_ThrowsEncryptionProviderException()
        throws EncryptionProviderException {
        // given
        when(aesGcmSealingKeyProvider.encrypt(any())).thenThrow(new EncryptionProviderException("test"));

        // when-then
        final BKPInternalServerException exception = assertThrows(BKPInternalServerException.class,
            () -> sut.save(appraisalPolicyDTO)
        );

        // then
        verifyExpectedErrorCode(exception,
            ErrorCodeMap.FAILED_TO_ENCRYPT_SENSITIVE_DATA_WITH_SEALING_KEY);
    }

    @Test
    void delete_ThrowsNotFoundException() {
        // given
        long id = 10L;

        // when
        assertThrows(AppraisalPolicyNotFound.class,
            () -> sut.delete(id)
        );

        // then
        verify(appraisalPolicyRepository, never()).deleteById(id);
    }

    @Test
    void delete() {
        // given
        long id = 10L;
        when(appraisalPolicyRepository.existsById(id)).thenReturn(true);

        // when
        sut.delete(10L);

        // then
        verify(appraisalPolicyRepository).deleteById(id);
    }

    @Test
    void findAllForResponse() {
        // given
        when(appraisalPolicyRepository.findAll()).thenReturn(Collections.singletonList(encryptedAppraisalPolicy));
        when(appraisalPolicyMapper.toResultDto(encryptedAppraisalPolicy)).thenReturn(appraisalPolicyResponseDTO);

        // when
        List<AppraisalPolicyResponseDTO> result = sut.findAllForResponse();

        // then
        assertArrayEquals(
            Collections.singletonList(appraisalPolicyResponseDTO).toArray(), result.toArray());

    }

    @Test
    void findOneForDetails() throws EncryptionProviderException {
        // given
        long id = 1L;
        when(appraisalPolicyRepository.findById(id)).thenReturn(Optional.of(encryptedAppraisalPolicy));
        when(encryptedAppraisalPolicy.getContent()).thenReturn(toHex(encryptedContentHex));
        when(aesGcmSealingKeyProvider.decrypt(encryptedContentHex)).thenReturn(appraisalPolicyContent.getBytes(
            StandardCharsets.UTF_8));

        // when
        Optional<String> result = sut.findOneForDetails(id);

        // then
        verify(aesGcmSealingKeyProvider).decrypt(encryptedContentHex);
        assertEquals(Optional.ofNullable(appraisalPolicyContent), result);

    }

    private void mockActiveSealingKeyExists() {
        when(sealingKeyManager.isActiveSealingKey()).thenReturn(true);
    }

    private void mockActiveSealingKeyDoesNotExist() {
        when(sealingKeyManager.isActiveSealingKey()).thenReturn(false);
    }

    private void mockPendingSealingKeyExists() {
        when(sealingKeyManager.isPendingSealingKey()).thenReturn(true);
    }

    private void mockPendingSealingKeyDoesNotExist() {
        when(sealingKeyManager.isPendingSealingKey()).thenReturn(false);
    }
}
