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
import com.intel.bkp.bkps.domain.enumeration.SealingKeyStatus;
import com.intel.bkp.bkps.repository.SealingKeyRepository;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.initialization.model.dto.SealingKeyResponseDTO;
import com.intel.bkp.bkps.rest.initialization.model.mapper.SealingKeyMapper;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.SecurityKeyType;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import javax.crypto.SecretKey;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import static lombok.AccessLevel.PACKAGE;

@Component
@Transactional(isolation = Isolation.SERIALIZABLE)
@AllArgsConstructor(access = PACKAGE)
@Slf4j
public class SealingKeyManager {

    private final ISecurityProvider securityService;
    private final SealingKeyRepository sealingKeyRepository;
    private final SealingKeyMapper sealingKeyMapper;
    private final ApplicationEventPublisher eventPublisher;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_ROLLBACK)
    public void rollbackKeyInSecurityService(SealingKeyCreationEvent event) {
        securityService.deleteSecurityObject(event.getSealingKeyGuid());
    }

    public void createActiveKey() {
        createNewSealingKeyWithStatus(SealingKeyStatus.ENABLED);
    }

    public void createPendingKey() {
        createNewSealingKeyWithStatus(SealingKeyStatus.PENDING);
    }

    public SecretKey createExportablePendingKey() throws KeystoreGenericException {
        return createNewExportableSealingKeyWithStatusPending();
    }

    public void importSecretKeyAsPending(SecretKey secretKey) {
        createNewExportableSealingKeyWithStatusPendingAndKey(secretKey);
    }

    public SecretKey getActiveKey() {
        Optional<SealingKey> sealingKey = getActiveSealingKeyFromDatabase();
        return getSecretKey(sealingKey);
    }

    public SecretKey getPendingKey() {
        Optional<SealingKey> sealingKey = getPendingSealingKeyFromDatabase();
        return getSecretKey(sealingKey);
    }

    public void disableActiveKey() {
        getActiveSealingKeyFromDatabase().ifPresent(key -> {
            key.setStatus(SealingKeyStatus.DISABLED);
            sealingKeyRepository.save(key);
        });
    }

    public void activatePendingKey() {
        getPendingSealingKeyFromDatabase().ifPresent(key -> {
            key.setStatus(SealingKeyStatus.ENABLED);
            sealingKeyRepository.save(key);
        });
    }

    public void disablePendingKey() {
        getPendingSealingKeyFromDatabase().ifPresent(key -> {
            key.setStatus(SealingKeyStatus.DISABLED);
            sealingKeyRepository.save(key);
        });
    }

    @Async("taskExecutor")
    public void disablePendingKeyAsync() {
        disablePendingKey();
    }

    public List<SealingKeyResponseDTO> list() {
        log.debug("Request to get all sealing keys.");
        return sealingKeyRepository.findAll().stream()
            .sorted(Comparator.comparing(SealingKey::getId))
            .map(sealingKeyMapper::toResultDto)
            .collect(Collectors.toCollection(LinkedList::new));
    }

    public boolean isActiveSealingKey() {
        Optional<SealingKey> activeSealingKey = getActiveSealingKeyFromDatabase();
        return isKeyPresent(activeSealingKey);
    }

    public boolean isPendingSealingKey() {
        Optional<SealingKey> pendingSealingKey = getPendingSealingKeyFromDatabase();
        return isKeyPresent(pendingSealingKey);
    }

    public boolean isActiveSealingKeyInDatabase() {
        return getActiveSealingKeyFromDatabase().isPresent();
    }

    SecretKey getSecretKey(Optional<SealingKey> sealingKeyOptional) {
        if (!isKeyPresent(sealingKeyOptional)) {
            throw new BKPBadRequestException(ErrorCodeMap.SEALING_KEY_DOES_NOT_EXIST);
        }

        return sealingKeyOptional
            .map(sealingKey -> securityService.getKeyFromSecurityObject(sealingKey.getGuid()))
            .orElse(null);
    }

    boolean isKeyPresent(Optional<SealingKey> sealingKey) {
        return sealingKey.map(key -> {
            if (!securityService.existsSecurityObject(key.getGuid())) {
                throw new BKPInternalServerException(ErrorCodeMap.SEALING_KEY_EXISTS_IN_DB_BUT_NOT_ENCLAVE,
                    key + " does not exist in security enclave but exists in database.");
            }
            return true;
        }).orElse(false);
    }

    private void createNewSealingKeyWithStatus(SealingKeyStatus status) {
        String securityObjectId = generateNewGuid();
        registerRollbackEvent(securityObjectId);

        createNewSecurityObjectInSecureEnclave(securityObjectId);
        verifyIfSealingKeyCreatedSuccessfully(securityObjectId);
        saveNewSealingKeyInDatabase(securityObjectId, status);
    }

    private SecretKey createNewExportableSealingKeyWithStatusPending() throws KeystoreGenericException {
        SecretKey secretKey = CryptoUtils.genAesBC();
        createNewExportableSealingKeyWithStatusPendingAndKey(secretKey);
        return secretKey;
    }

    private void createNewExportableSealingKeyWithStatusPendingAndKey(SecretKey secretKey) {
        String securityObjectId = generateNewGuid();
        registerRollbackEvent(securityObjectId);

        importSecretKeyToSecurityEnclave(securityObjectId, secretKey);
        verifyIfSealingKeyCreatedSuccessfully(securityObjectId);
        saveNewSealingKeyInDatabase(securityObjectId, SealingKeyStatus.PENDING);
    }

    private void registerRollbackEvent(String securityObjectId) {
        eventPublisher.publishEvent(new SealingKeyCreationEvent(securityObjectId));
    }

    private Optional<SealingKey> getActiveSealingKeyFromDatabase() {
        return getSealingKeyByStatus(SealingKeyStatus.ENABLED);
    }

    private Optional<SealingKey> getPendingSealingKeyFromDatabase() {
        return getSealingKeyByStatus(SealingKeyStatus.PENDING);
    }

    private Optional<SealingKey> getSealingKeyByStatus(SealingKeyStatus status) {
        return sealingKeyRepository.findOne(sealingKeyRepository.findByStatus(status));
    }

    private String generateNewGuid() {
        return UUID.randomUUID().toString();
    }

    private void createNewSecurityObjectInSecureEnclave(String securityObjectId) {
        securityService.createSecurityObject(SecurityKeyType.AES, securityObjectId);
    }

    private void verifyIfSealingKeyCreatedSuccessfully(String securityObjectId) {
        if (!securityService.existsSecurityObject(securityObjectId)) {
            throw new BKPInternalServerException(ErrorCodeMap.FAILED_TO_SAVE_SEALING_KEY_IN_SECURITY_ENCLAVE);
        }
    }

    private void saveNewSealingKeyInDatabase(String securityObjectId, SealingKeyStatus status) {
        sealingKeyRepository.save(new SealingKey()
            .guid(securityObjectId)
            .status(status)
        );
    }

    private void importSecretKeyToSecurityEnclave(String securityObjectId, SecretKey secretKey) {
        securityService.importSecretKey(securityObjectId, secretKey);
    }
}
