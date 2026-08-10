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

import com.intel.bkp.bkps.domain.SealingKeyBackupHash;
import com.intel.bkp.bkps.exception.SealingKeyBackupHashDoesNotExistException;
import com.intel.bkp.bkps.exception.SealingKeyBackupHashDoesNotMatchException;
import com.intel.bkp.bkps.repository.SealingKeyBackupHashRepository;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import static lombok.AccessLevel.PACKAGE;

@Component
@Transactional(isolation = Isolation.SERIALIZABLE)
@AllArgsConstructor(access = PACKAGE)
@Slf4j
public class SealingKeyBackupHashManager {

    private final SealingKeyBackupHashRepository sealingKeyBackupHashRepository;

    public void update(byte[] encryptedBackupKey) {
        deleteAll();
        sealingKeyBackupHashRepository.save(new SealingKeyBackupHash(getHash(encryptedBackupKey)));
    }

    public void verify(byte[] encryptedBackupKey) throws SealingKeyBackupHashDoesNotExistException,
        SealingKeyBackupHashDoesNotMatchException {

        SealingKeyBackupHash entity = sealingKeyBackupHashRepository.findFirstByOrderByIdDesc()
            .orElseThrow(SealingKeyBackupHashDoesNotExistException::new);
        if (!hashMatches(entity, encryptedBackupKey)) {
            throw new SealingKeyBackupHashDoesNotMatchException();
        }
    }

    public void deleteAll() {
        sealingKeyBackupHashRepository.deleteAll();
    }

    private boolean hashMatches(SealingKeyBackupHash entity, byte[] encryptedBackupKey) {
        return entity.getHash().equals(getHash(encryptedBackupKey));
    }

    private String getHash(byte[] encryptedBackupKey) {
        return DigestUtils.sha256Hex(encryptedBackupKey);
    }
}
