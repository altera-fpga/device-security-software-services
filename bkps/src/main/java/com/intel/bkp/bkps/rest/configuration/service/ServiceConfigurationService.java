/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2025 Altera Corporation. All Rights Reserved.
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

import com.intel.bkp.bkps.crypto.aesctr.AesCtrEncryptionKeyProviderImpl;
import com.intel.bkp.bkps.crypto.aesgcm.AesGcmSealingKeyProviderImpl;
import com.intel.bkp.bkps.crypto.sealingkey.SealingKeyManager;
import com.intel.bkp.bkps.domain.AesKey;
import com.intel.bkp.bkps.domain.Qek;
import com.intel.bkp.bkps.domain.ConfidentialData;
import com.intel.bkp.bkps.domain.enumeration.ImportMode;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.exception.ServiceConfigurationNotFound;
import com.intel.bkp.bkps.repository.ServiceConfigurationRepository;
import com.intel.bkp.bkps.rest.configuration.model.dto.ServiceConfigurationDTO;
import com.intel.bkp.bkps.rest.configuration.model.dto.ServiceConfigurationDetailsDTO;
import com.intel.bkp.bkps.rest.configuration.model.dto.ServiceConfigurationResponseDTO;
import com.intel.bkp.bkps.rest.configuration.model.mapper.ServiceConfigurationDetailsMapper;
import com.intel.bkp.bkps.rest.configuration.model.mapper.ServiceConfigurationMapper;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.endianness.StructureBuilder;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.interfaces.IStructure;
import com.intel.bkp.core.psgcertificate.IPsgAesKeyBuilder;
import com.intel.bkp.core.psgcertificate.PsgAesKeyBuilderFactory;
import com.intel.bkp.core.psgcertificate.PsgQekBuilderHSM;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import com.intel.bkp.core.psgcertificate.model.PsgAesKeyType;
import com.intel.bkp.crypto.aesctr.AesCtrQekIvProvider;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.crypto.exceptions.HMacProviderException;
import com.intel.bkp.crypto.hmac.HMacKdfProviderImpl;
import com.intel.bkp.utils.ByteConverter;
import org.apache.commons.codec.digest.DigestUtils;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static lombok.AccessLevel.PACKAGE;

/**
 * Service Implementation for managing ServiceConfiguration.
 */
@Service
@Transactional(isolation = Isolation.SERIALIZABLE)
@RequiredArgsConstructor(access = PACKAGE)
@Slf4j
public class ServiceConfigurationService {

    private final ServiceConfigurationRepository serviceConfigurationRepository;
    private final ServiceConfigurationDetailsMapper serviceConfigurationDetailsMapper;
    private final ServiceConfigurationMapper serviceConfigurationMapper;
    private final AesGcmSealingKeyProviderImpl aesGcmSealingKeyProvider;
    private final AesCtrEncryptionKeyProviderImpl aesCtrEncryptionKeyProvider;
    private final SealingKeyManager sealingKeyManager;
    private final ServiceConfigurationImportManager serviceConfigurationImportManager;

    @Setter(AccessLevel.PACKAGE)
    private PsgAesKeyBuilderFactory psgAesKeyBuilderFactory = new PsgAesKeyBuilderFactory();
    private IPsgAesKeyBuilder<? extends StructureBuilder<?, ? extends IStructure>> aesKeyBuilder;

    /**
     * Save a serviceConfiguration.
     *
     * @param serviceConfigurationDTO the entity to save
     *
     * @return the persisted entity
     */
    public ServiceConfigurationDTO save(ServiceConfigurationDTO serviceConfigurationDTO) {
        throwIfSealingKeyRotationPending();
        throwIfNoActiveSealingKey();

        final var config = serviceConfigurationMapper.toEntity(serviceConfigurationDTO);

        if (ImportMode.ENCRYPTED.equals(config.getConfidentialData().getImportMode())) {
            serviceConfigurationImportManager.decrypt(config.getConfidentialData());
        }

        final AesKey aesKey = config.getConfidentialData().getAesKey();
        setAesKeyDetails(aesKey);
        final Qek qek = config.getConfidentialData().getQek();
        if (PsgAesKeyType.SDM_1_5.equals(aesKeyBuilder.getAesKeyType())) {
            validateAESAndQek(qek);
        }

        encryptConfidentialData(config.getConfidentialData());

        final var savedConfig = serviceConfigurationRepository.save(config);
        log.info("Configuration {} saved.", savedConfig.getId());
        return serviceConfigurationMapper.toDto(savedConfig);
    }

    private void validateAESAndQek(Qek qek) {
        try {
            if (qek == null) {
                throw new IOException("QEK information is missing from the configuration JSON string");
            }

            // Parse & Validate AES ccert data and QEK data
            PsgQekBuilderHSM qekBuilderHSM = new PsgQekBuilderHSM();
            qekBuilderHSM.withActor(EndiannessActor.FIRMWARE).parse(fromHex(qek.getValue()));

            // Decrypt and extract actual AES root key from QEK data
            aesCtrEncryptionKeyProvider.initialize(new AesCtrQekIvProvider(qekBuilderHSM.getIvData()), qek.getKeyName());
            byte[] aesRootKey = new byte[32];
            byte[] kdkKey = new byte[32];
            byte[] expectedSHA384Hash = new byte[48];

            Integer version = ByteConverter.toInt(qekBuilderHSM.getVersion());
            // Verify hash of QEK
            if (version == 1) {
                // Decrypt block of AES key, KDK and SHA384 hash
                ByteBuffer buffer = ByteBuffer.allocate(0x70);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.put(qekBuilderHSM.getEncryptedAESKey());
                buffer.put(qekBuilderHSM.getEncryptedKDK());
                buffer.put(qekBuilderHSM.getEncryptedSHA384());
                byte[] decodedData = aesCtrEncryptionKeyProvider.decrypt(buffer.array());
                ByteBuffer decodedBuffer = ByteBuffer.wrap(decodedData);
                decodedBuffer.get(aesRootKey);
                decodedBuffer.get(kdkKey);
                decodedBuffer.get(expectedSHA384Hash);
            } else {
                aesRootKey = aesCtrEncryptionKeyProvider.decrypt(qekBuilderHSM.getEncryptedAESKey());
                kdkKey = aesCtrEncryptionKeyProvider.decrypt(qekBuilderHSM.getEncryptedKDK());
                expectedSHA384Hash = aesCtrEncryptionKeyProvider.decrypt(qekBuilderHSM.getEncryptedSHA384());
            }

            ByteBuffer bufferCheckHash = ByteBuffer.allocate(0x60);
            bufferCheckHash.order(ByteOrder.LITTLE_ENDIAN);
            bufferCheckHash.put(qekBuilderHSM.getReservedNoSalt());
            bufferCheckHash.put(qekBuilderHSM.getIvData());
            bufferCheckHash.put(aesRootKey);
            bufferCheckHash.put(kdkKey);
            byte[] sha384Hash = DigestUtils.sha384(bufferCheckHash.array());
            if (!Arrays.equals(sha384Hash, expectedSHA384Hash)) {
                throw new IOException("Failed to decrypt QEK data. QEK data is either corrupted or QEK encryption key that associated with the key name is mismatch.");
            }

            // Compute KI-MAC tag of AES Root Key
            final byte[] knownBytes = new byte[32];
            Arrays.fill(knownBytes, (byte) 0);
            ByteBuffer kiMacData = ByteBuffer.allocate(64);
            // Concatenate 256-bits zero of known message and KI-MAC data
            kiMacData.put(knownBytes);
            kiMacData.put(aesKeyBuilder.getMacData());
            final byte[] macTag = new HMacKdfProviderImpl(aesRootKey).getHash(kiMacData.array());

            // Verify KI-HMAC tag of AES Root Key using AES ccert data
            if (!Arrays.equals(macTag, aesKeyBuilder.getMacTag())) {
                throw new IOException("The AES key is mismatch with QEK. The AES key must be generated using the same input QEK.");
            }

        } catch (EncryptionProviderException e) {
            throw new BKPInternalServerException(ErrorCodeMap.FAILED_TO_DECRYPT_UPLOADED_SENSITIVE_DATA, e);
        } catch (ParseStructureException | IOException | HMacProviderException e) {
            throw new BKPBadRequestException(ErrorCodeMap.CORRUPTED_QEK, e);
        }
    }

    private void setAesKeyDetails(AesKey aesKey) {
        try {
            final var aesKeyBytes = fromHex(aesKey.getValue());
            aesKeyBuilder = getPsgAesKeySDMType(aesKeyBytes);

            parseKey(aesKeyBytes, aesKeyBuilder);
            aesKey.setStorage(aesKeyBuilder.getStorageType());
            aesKey.setKeyWrappingType(aesKeyBuilder.getKeyWrappingType());
            verifyEfusesStorageTypeRequiredField(aesKey, aesKeyBuilder.getAesKeyType());
            handleTestFlag(aesKey, aesKeyBuilder.getAesKeyType());
        } catch (ParseStructureException e) {
            throw new BKPBadRequestException(ErrorCodeMap.CORRUPTED_AES_KEY, e);
        }
    }

    private void handleTestFlag(AesKey aesKeyFromDTO, PsgAesKeyType type) {
        if (aesKeyFromDTO.getTestProgram() != null) {
            if (!type.getTestprogramSupported()) {
                if (aesKeyFromDTO.getTestProgram()) {
                    log.warn("Compact certificate version (%d) does not support testProgram flag. Hence, resetting it to false.".formatted(type.getVersion()));
                    aesKeyFromDTO.setTestProgram(false);
                }
            }
        } else {
            aesKeyFromDTO.setTestProgram(false);
        }
    }

    private void verifyEfusesStorageTypeRequiredField(AesKey aesKey, PsgAesKeyType type) {
        if (PsgAesKeyType.SDM_1_2.equals(type)
            && StorageType.EFUSES == aesKey.getStorage()
            && aesKey.getTestProgram() == null) {
            throw new BKPBadRequestException(ErrorCodeMap.MISSING_FLAG_TEST_PROGRAM);
        }
    }

    private IPsgAesKeyBuilder<? extends StructureBuilder<?, ? extends IStructure>> getPsgAesKeySDMType(
        byte[] decryptedAesKey) {
        try {
            return psgAesKeyBuilderFactory
                .withActor(EndiannessActor.FIRMWARE)
                .getPsgAesKeyBuilder(decryptedAesKey);
        } catch (ParseStructureException e) {
            throw new ProvisioningGenericException("Failed to get AES Key SDM version.", e);
        }
    }

    private void parseKey(byte[] decryptedAesKey,
                          IPsgAesKeyBuilder<? extends StructureBuilder<?, ? extends IStructure>> builder) {
        try {
            builder.withActor(EndiannessActor.FIRMWARE).parse(decryptedAesKey);
        } catch (ParseStructureException e) {
            throw new BKPBadRequestException(ErrorCodeMap.CORRUPTED_AES_KEY, e);
        }
    }

    /**
     * Get all the serviceConfigurations.
     *
     * @return the list of entities
     */
    @Transactional(readOnly = true)
    public List<ServiceConfigurationResponseDTO> findAllForResponse() {
        log.debug("Request to get all ServiceConfigurations");
        return serviceConfigurationRepository.findAll().stream()
            .map(serviceConfigurationMapper::toResultDto)
            .collect(Collectors.toCollection(LinkedList::new));
    }

    /**
     * Get one serviceConfiguration by id.
     *
     * @param id the id of the entity
     *
     * @return the entity
     */
    @Transactional(readOnly = true)
    public Optional<ServiceConfigurationDetailsDTO> findOneForDetails(Long id) {
        log.debug("Request to get ServiceConfiguration : {}", id);
        return serviceConfigurationRepository.findById(id)
            .map(serviceConfigurationDetailsMapper::toDto);
    }

    /**
     * Delete the serviceConfiguration by id.
     *
     * @param id the id of the entity
     */
    public void delete(Long id) {
        log.debug("Request to delete ServiceConfiguration : {}", id);

        if (!exists(id)) {
            throw new ServiceConfigurationNotFound();
        }

        serviceConfigurationRepository.deleteById(id);
    }

    public boolean exists(Long id) {
        return serviceConfigurationRepository.existsById(id);
    }

    private void encryptConfidentialData(ConfidentialData confidentialData) {
        aesGcmSealingKeyProvider.initialize(sealingKeyManager.getActiveKey());

        byte[] customerAesKey = fromHex(confidentialData.getAesKey().getValue());

        confidentialData.getAesKey().setValue(encryptInternal(customerAesKey));

        if (confidentialData.getQek() != null) {
            byte[] customerQek = fromHex(confidentialData.getQek().getValue());

            confidentialData.getQek().setValue(encryptInternal(customerQek));
        }
    }

    private void throwIfNoActiveSealingKey() {
        if (!sealingKeyManager.isActiveSealingKey()) {
            throw new BKPBadRequestException(ErrorCodeMap.ACTIVE_SEALING_KEY_DOES_NOT_EXIST);
        }
    }

    private void throwIfSealingKeyRotationPending() {
        if (sealingKeyManager.isPendingSealingKey()) {
            throw new BKPBadRequestException(ErrorCodeMap.SEALING_KEY_ROTATION_PENDING);
        }
    }

    private String encryptInternal(byte[] data) {
        try {
            return toHex(aesGcmSealingKeyProvider.encrypt(data));
        } catch (EncryptionProviderException e) {
            throw new BKPInternalServerException(ErrorCodeMap.FAILED_TO_ENCRYPT_SENSITIVE_DATA_WITH_SEALING_KEY, e);
        }
    }
}
