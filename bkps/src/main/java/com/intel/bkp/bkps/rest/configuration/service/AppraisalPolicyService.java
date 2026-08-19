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

import com.fasterxml.jackson.core.JsonProcessingException;
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
import com.intel.bkp.fpgacerts.appraisalpolicy.parser.AppraisalPolicyParser;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static lombok.AccessLevel.PACKAGE;

/**
 * Service Implementation for managing AppraisalPolicy.
 */
@Service
@Transactional(isolation = Isolation.SERIALIZABLE)
@RequiredArgsConstructor(access = PACKAGE)
@Slf4j
public class AppraisalPolicyService {

    private final AppraisalPolicyRepository appraisalPolicyRepository;
    private final AppraisalPolicyMapper appraisalPolicyMapper;
    private final AesGcmSealingKeyProviderImpl aesGcmSealingKeyProvider;
    private final SealingKeyManager sealingKeyManager;

    /**
     * Save a appraisalPolicy.
     *
     * @param appraisalPolicyDTO the entity to save
     *
     * @return the persisted entity
     */
    public AppraisalPolicyResponseDTO save(AppraisalPolicyDTO appraisalPolicyDTO) {
        try {
            throwIfSealingKeyRotationPending();
            throwIfNoActiveSealingKey();
            final var entity = appraisalPolicyMapper.toEntity(appraisalPolicyDTO);
            final var parsedPolicy = AppraisalPolicyParser.instance().parse(entity.getContent());
            ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
            Validator validator = factory.getValidator();
            final var violations = validator.validate(parsedPolicy);
            if (!violations.isEmpty()) {
                throw new BKPBadRequestException(ErrorCodeMap.CORRUPTED_APPRAISAL_POLICY);
            }
            aesGcmSealingKeyProvider.initialize(sealingKeyManager.getActiveKey());
            entity.setContent(encryptInternal(entity));
            final var savedPolicy = appraisalPolicyRepository.save(entity);
            log.info("Policy {} saved.", savedPolicy.getId());
            return appraisalPolicyMapper.toResultDto(savedPolicy);
        } catch (JsonProcessingException e) {
            throw new BKPBadRequestException(ErrorCodeMap.CORRUPTED_APPRAISAL_POLICY);
        }
    }

    /**
     * Get all the appraisalPolicies.
     *
     * @return the list of entities
     */
    @Transactional(readOnly = true)
    public List<AppraisalPolicyResponseDTO> findAllForResponse() {
        log.debug("Request to get all AppraisalPolicies");
        return appraisalPolicyRepository.findAll().stream()
            .map(appraisalPolicyMapper::toResultDto)
            .collect(Collectors.toCollection(LinkedList::new));
    }

    /**
     * Get one appraisalPolicy by id.
     *
     * @param id the id of the entity
     *
     * @return the entity
     */
    @Transactional(readOnly = true)
    public Optional<String> findOneForDetails(Long id) {
        log.debug("Request to get AppraisalPolicy : {}", id);
        throwIfSealingKeyRotationPending();
        throwIfNoActiveSealingKey();
        aesGcmSealingKeyProvider.initialize(sealingKeyManager.getActiveKey());
        return appraisalPolicyRepository.findById(id)
            .map(entity -> new String(decryptInternal(entity), StandardCharsets.UTF_8).trim());
    }

    /**
     * Delete the appraisalPolicy by id.
     *
     * @param id the id of the entity
     */
    public void delete(Long id) {
        log.debug("Request to delete AppraisalPolicy : {}", id);
        if (!exists(id)) {
            throw new AppraisalPolicyNotFound();
        }
        appraisalPolicyRepository.deleteById(id);
    }

    public boolean exists(Long id) {
        return appraisalPolicyRepository.existsById(id);
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

    private String encryptInternal(AppraisalPolicy appraisalPolicy) {
        try {
            return toHex(aesGcmSealingKeyProvider.encrypt(appraisalPolicy.getContent().getBytes(StandardCharsets.UTF_8)));
        } catch (EncryptionProviderException e) {
            throw new BKPInternalServerException(ErrorCodeMap.FAILED_TO_ENCRYPT_SENSITIVE_DATA_WITH_SEALING_KEY, e);
        }
    }

    private byte[] decryptInternal(AppraisalPolicy appraisalPolicy) {
        try {
            return aesGcmSealingKeyProvider.decrypt(fromHex(appraisalPolicy.getContent()));
        } catch (EncryptionProviderException e) {
            throw new BKPInternalServerException(ErrorCodeMap.FAILED_TO_DECRYPT_UPLOADED_SENSITIVE_DATA, e);
        }
    }
}
