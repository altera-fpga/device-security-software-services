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

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmSealingKeyProviderImpl;
import com.intel.bkp.bkps.crypto.sealingkey.event.SealingKeyTransactionEvent;
import com.intel.bkp.bkps.domain.AesKey;
import com.intel.bkp.bkps.repository.AesKeyRepository;
import com.intel.bkp.core.exceptions.BKPInternalRuntimeException;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import javax.crypto.SecretKey;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static lombok.AccessLevel.PACKAGE;

@Component
@RequiredArgsConstructor(access = PACKAGE)
@Slf4j
public class SealingKeyRotationTransaction {

    private final AesKeyRepository aesKeyRepository;
    private final AesGcmSealingKeyProviderImpl encryptionProvider;
    private final SealingKeyManager sealingKeyManager;
    private final ApplicationEventPublisher eventPublisher;

    @Async("taskExecutor")
    @Transactional(isolation = Isolation.SERIALIZABLE)
    public void reencryptAllAssetsAndActivatePendingKey(SecretKey activeKey, SecretKey pendingKey) {
        log.debug("Starting reencryption of all assets with new sealing key.");
        registerRollbackEvent();

        try {
            reencryptAllAesKey(activeKey, pendingKey);
            sealingKeyManager.disableActiveKey();
            sealingKeyManager.activatePendingKey();
        } catch (Exception e) {
            throw new BKPInternalRuntimeException("Exception occurred during Sealing Key rotation.", e);
        }
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_ROLLBACK)
    public void rollbackPendingKey(SealingKeyTransactionEvent event) {
        log.error("Reencryption of ServiceConfigurations failed. Disabling PENDING Sealing Key.");
        sealingKeyManager.disablePendingKeyAsync();
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void logProcessCompleted(SealingKeyTransactionEvent event) {
        log.info("Finished to reencrypt all ServiceConfigurations.");
    }

    private void registerRollbackEvent() {
        eventPublisher.publishEvent(new SealingKeyTransactionEvent());
    }

    private void reencryptAllAesKey(SecretKey activeKey, SecretKey pendingKey) throws EncryptionProviderException {
        for (AesKey key : aesKeyRepository.findAll()) {
            String encodedKey = reencrypt(activeKey, pendingKey, key.getValue());
            key.setValue(encodedKey);
            aesKeyRepository.save(key);
        }
    }

    private String reencrypt(SecretKey activeKey, SecretKey pendingKey, String value)
        throws EncryptionProviderException {

        byte[] decodedKey = fromHex(value);
        encryptionProvider.initialize(activeKey);
        byte[] decrypted = encryptionProvider.decrypt(decodedKey);
        encryptionProvider.initialize(pendingKey);
        byte[] encrypted = encryptionProvider.encrypt(decrypted);
        return toHex(encrypted);
    }
}
