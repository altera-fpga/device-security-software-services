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
import com.intel.bkp.bkps.domain.AesKey;
import com.intel.bkp.bkps.domain.ConfidentialData;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.domain.enumeration.ImportMode;
import com.intel.bkp.bkps.exception.ServiceConfigurationNotFound;
import com.intel.bkp.bkps.repository.ServiceConfigurationRepository;
import com.intel.bkp.bkps.rest.configuration.model.dto.ServiceConfigurationDTO;
import com.intel.bkp.bkps.rest.configuration.model.dto.ServiceConfigurationDetailsDTO;
import com.intel.bkp.bkps.rest.configuration.model.dto.ServiceConfigurationResponseDTO;
import com.intel.bkp.bkps.rest.configuration.model.mapper.ServiceConfigurationDetailsMapper;
import com.intel.bkp.bkps.rest.configuration.model.mapper.ServiceConfigurationMapper;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.core.psgcertificate.IPsgAesKeyBuilder;
import com.intel.bkp.core.psgcertificate.PsgAesKeyBuilderFactory;
import com.intel.bkp.core.psgcertificate.PsgAesKeyBuilderSDM12;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static com.intel.bkp.test.AssertionUtils.verifyExpectedErrorCode;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class ServiceConfigurationServiceTest {

    private static final String AES_KEY_INVALID_LEN = StringUtils.repeat("00", 4);

    @Mock
    private ServiceConfigurationRepository serviceConfigurationRepository;

    @Mock
    private ServiceConfigurationDetailsMapper serviceConfigurationDetailsMapper;

    @Mock
    private ServiceConfigurationMapper serviceConfigurationMapper;

    @Mock
    private AesGcmSealingKeyProviderImpl aesGcmSealingKeyProvider;

    @Mock
    private SealingKeyManager sealingKeyManager;

    @Mock
    private ServiceConfigurationImportManager serviceConfigurationImportManager;

    @Mock
    private ServiceConfiguration serviceConfiguration;

    @Mock
    private ConfidentialData confidentialData;

    @Mock
    private AesKey aesKey;

    @Mock
    private ServiceConfigurationDTO serviceConfigurationDTO;

    @Mock
    private ServiceConfigurationResponseDTO serviceConfigurationResponseDTO;

    @Mock
    private ServiceConfigurationDetailsDTO serviceConfigurationDetailsDTO;

    @Mock
    PsgAesKeyBuilderFactory psgAesKeyBuilderFactory;

    @InjectMocks
    private ServiceConfigurationService sut;

    @BeforeEach
    void setUp() throws Exception {
        when(serviceConfiguration.getId()).thenReturn(1L);
        when(serviceConfiguration.getConfidentialData()).thenReturn(confidentialData);
        when(confidentialData.getImportMode()).thenReturn(ImportMode.PLAINTEXT);
        when(confidentialData.getAesKey()).thenReturn(aesKey);

        final byte[] aesContent = loadExampleAesKey("signed_iid_aes.ccert");
        when(aesKey.getValue()).thenReturn(toHex(aesContent));

        when(aesGcmSealingKeyProvider.encrypt(any())).thenReturn(new byte[32]);
        when(serviceConfigurationMapper.toEntity(serviceConfigurationDTO)).thenReturn(serviceConfiguration);
        when(serviceConfigurationRepository.save(any())).thenReturn(serviceConfiguration);
        when(serviceConfigurationMapper.toDto(serviceConfiguration)).thenReturn(serviceConfigurationDTO);
        mockPendingSealingKeyDoesNotExist();
        mockActiveSealingKeyExists();

        sut.setPsgAesKeyBuilderFactory(psgAesKeyBuilderFactory);
        when(psgAesKeyBuilderFactory.withActor(any())).thenReturn(psgAesKeyBuilderFactory);
        IPsgAesKeyBuilder<?> builder = new PsgAesKeyBuilderSDM12();
        Mockito.doReturn(builder).when(psgAesKeyBuilderFactory).getPsgAesKeyBuilder(any());
    }

    @Test
    void save_WithPlaintextMode_DoesNotCallDecrypt() {
        // when
        sut.save(serviceConfigurationDTO);

        // then
        verify(serviceConfigurationImportManager, never()).decrypt(any());
    }

    @Test
    void save_WithEncryptedMode_CallsDecrypt() {
        // given
        when(confidentialData.getImportMode()).thenReturn(ImportMode.ENCRYPTED);

        // when
        sut.save(serviceConfigurationDTO);

        // then
        verify(serviceConfigurationImportManager).decrypt(confidentialData);
    }

    @Test
    void save_CallsSave() {
        // when
        sut.save(serviceConfigurationDTO);

        // then
        verify(serviceConfigurationRepository).save(serviceConfiguration);
    }

    @Test
    void save_ReturnsProperDto() {
        // when
        ServiceConfigurationDTO result = sut.save(serviceConfigurationDTO);

        // then
        assertEquals(serviceConfigurationDTO, result);
    }

    @Test
    void save_InvalidAesKeyLen() {
        // given
        when(aesKey.getValue()).thenReturn(AES_KEY_INVALID_LEN);

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.save(serviceConfigurationDTO)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.CORRUPTED_AES_KEY);
    }

    @Test
    void save_WithNoTestProgramWithEfuses_Throws() {
        // given
        when(aesKey.getStorage()).thenReturn(StorageType.EFUSES);
        when(aesKey.getTestProgram()).thenReturn(null);

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.save(serviceConfigurationDTO)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.MISSING_FLAG_TEST_PROGRAM);
    }

    @Test
    void save_WithTestProgramWithEfuses_NoThrow() {
        // given
        when(aesKey.getStorage()).thenReturn(StorageType.EFUSES);
        when(aesKey.getTestProgram()).thenReturn(true);

        // when-then
        assertDoesNotThrow(() -> sut.save(serviceConfigurationDTO));

        // then
        verify(aesKey, never()).setTestProgram(false);
    }

    @Test
    void save_WithBBram_DoesNotCheckTestProgram() {
        // given
        when(aesKey.getStorage()).thenReturn(StorageType.BBRAM);
        when(aesKey.getTestProgram()).thenReturn(null);

        // then
        assertDoesNotThrow(() -> sut.save(serviceConfigurationDTO));
        verify(aesKey, times(1)).setTestProgram(false);
    }

    @Test
    void save_WithPufss_DoesNotCheckTestProgram() {
        // given
        when(aesKey.getStorage()).thenReturn(StorageType.PUFSS);
        when(serviceConfiguration.getPufType()).thenReturn(PufType.IID);
        when(aesKey.getTestProgram()).thenReturn(null);

        // then
        assertDoesNotThrow(() -> sut.save(serviceConfigurationDTO));
        verify(aesKey, times(1)).setTestProgram(false);
    }

    @Test
    void save_SealingKeyRotationPending_Throws() {
        // given
        mockPendingSealingKeyExists();

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.save(serviceConfigurationDTO)
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
            () -> sut.save(serviceConfigurationDTO)
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
            () -> sut.save(serviceConfigurationDTO)
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
        assertThrows(ServiceConfigurationNotFound.class,
            () -> sut.delete(id)
        );

        // then
        verify(serviceConfigurationRepository, never()).deleteById(id);
    }

    @Test
    void delete() {
        // given
        long id = 10L;
        when(serviceConfigurationRepository.existsById(id)).thenReturn(true);

        // when
        sut.delete(10L);

        // then
        verify(serviceConfigurationRepository).deleteById(id);
    }

    @Test
    void findAllForResponse() {
        // given
        when(serviceConfigurationRepository.findAll()).thenReturn(Collections.singletonList(serviceConfiguration));
        when(serviceConfigurationMapper.toResultDto(serviceConfiguration))
            .thenReturn(serviceConfigurationResponseDTO);

        // when
        List<ServiceConfigurationResponseDTO> result = sut.findAllForResponse();

        // then
        assertArrayEquals(
            Collections.singletonList(serviceConfigurationResponseDTO).toArray(), result.toArray());

    }

    @Test
    void findOneForDetails() {
        // given
        long id = 1L;
        when(serviceConfigurationRepository.findById(id)).thenReturn(Optional.of(serviceConfiguration));
        when(serviceConfigurationDetailsMapper.toDto(serviceConfiguration))
            .thenReturn(serviceConfigurationDetailsDTO);

        // when
        Optional<ServiceConfigurationDetailsDTO> result = sut.findOneForDetails(id);

        // then
        assertEquals(Optional.of(serviceConfigurationDetailsDTO), result);

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

    private byte[] loadExampleAesKey(String filename) throws IOException {
        Path path = Path.of("testdata", filename);
        try (InputStream inputStream = Objects.requireNonNull(
            ServiceConfigurationServiceTest.class.getResourceAsStream("/" + path))) {
            return inputStream.readAllBytes();
        }
    }
}
