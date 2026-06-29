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

package com.intel.bkp.bkps.rest.user.service;

import com.intel.bkp.bkps.domain.AppUser;
import com.intel.bkp.bkps.domain.DynamicCertificate;
import com.intel.bkp.bkps.exception.X509TrustManagerException;
import com.intel.bkp.bkps.repository.DynamicCertificateRepository;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.user.utils.RestartServerHelper;
import com.intel.bkp.bkps.security.X509TrustManagerManager;
import com.intel.bkp.bkps.utils.CertificateManager;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.crypto.exceptions.X509CertificateParsingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

@Service
@Slf4j
@RequiredArgsConstructor
public class DynamicCertificateService {

    private final DynamicCertificateRepository dynamicCertificateRepository;
    private final X509TrustManagerManager x509TrustManagerFactory;

    public void saveCertificateData(String userCertificate, String fingerprint, Instant validUntil, String alias) {
        updateTrustStore(userCertificate, alias);
        final DynamicCertificate user = DynamicCertificate.createUserCert(
            alias, fingerprint, validUntil, userCertificate
        );
        dynamicCertificateRepository.save(user);
        log.info("Added new certificate entry for created user: {}", alias);
        RestartServerHelper.restartServer();
    }

    public boolean fingerprintExists(String fingerprint) {
        return dynamicCertificateRepository.existsByFingerprint(fingerprint);
    }

    public void verifyNotExistInTruststore(String userCertificate) {
        try {
            if (x509TrustManagerFactory.fingerprintExists(
                CertificateManager.getCertificateFingerprint(userCertificate))
            ) {
                throw new BKPBadRequestException(ErrorCodeMap.CERTIFICATE_FINGERPRINT_EXISTS);
            }
        } catch (X509TrustManagerException | KeyStoreException | NoSuchAlgorithmException
                 | X509CertificateParsingException e) {
            throw new BKPInternalServerException(ErrorCodeMap.CERTIFICATE_IN_TRUSTSTORE_CHECK_FAILED, e);
        }
    }

    public void deleteDynamicCertForUser(AppUser appUser) {
        boolean anyDeleted = dynamicCertificateRepository
            .findByFingerprint(appUser.getFingerprint())
            .map(dynamicCertificate -> {
                softRemoveDynamicCertificate(dynamicCertificate);
                return removeCertificateFromTruststore(dynamicCertificate);
            }).orElse(false);
        if (anyDeleted) {
            RestartServerHelper.restartServer();
        }
    }

    private void updateTrustStore(String sentData, String alias) {
        try {
            x509TrustManagerFactory
                .addEntry(CertificateManager
                    .parseContent(sentData.getBytes(StandardCharsets.UTF_8)), alias);
        } catch (Exception e) {
            throw new BKPInternalServerException(ErrorCodeMap.SAVE_CERTIFICATE_IN_TRUSTSTORE_FAILED, e);
        }
    }

    private void softRemoveDynamicCertificate(DynamicCertificate dynamicCertificate) {
        dynamicCertificate.remove();
        dynamicCertificateRepository.save(dynamicCertificate);
    }

    private Boolean removeCertificateFromTruststore(DynamicCertificate dynamicCertificate) {
        try {
            if (x509TrustManagerFactory.exists(dynamicCertificate.getAlias())) {
                x509TrustManagerFactory.removeEntry(dynamicCertificate.getAlias());
                return true;
            }
        } catch (Exception e) {
            log.error("Failed to remove entry from truststore", e);
        }
        return false;
    }
}
