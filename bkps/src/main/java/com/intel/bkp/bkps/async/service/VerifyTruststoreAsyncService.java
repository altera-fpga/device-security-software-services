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

package com.intel.bkp.bkps.async.service;

import com.intel.bkp.bkps.BkpsApp;
import com.intel.bkp.bkps.async.model.TruststoreReloadSpringEvent;
import com.intel.bkp.bkps.domain.DynamicCertificate;
import com.intel.bkp.bkps.repository.DynamicCertificateRepository;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.security.X509TrustManagerManager;
import com.intel.bkp.bkps.utils.CertificateManager;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.core.helper.TruststoreCertificateEntryData;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class VerifyTruststoreAsyncService {

    private final DynamicCertificateRepository dynamicCertificateRepository;
    private final X509TrustManagerManager trustManagerFactory;

    @Value("${application.users.clean-removed-after-days}")
    private int cleanRemovedAfterDays;

    @Scheduled(cron = "${application.users.refresh-service-cron}", zone = "UTC")
    @EventListener(TruststoreReloadSpringEvent.class)
    public void synchronize() {
        log.debug("Verifying if truststore is synchronized with database.");

        List<DynamicCertificate> allCertificates = dynamicCertificateRepository.findAll();
        List<TruststoreCertificateEntryData> truststoreCertificates = getExistingCertsFromTruststore();

        int removedEntriesCounter = removeCertificates(filterRemovedItems(allCertificates), truststoreCertificates);
        int createdEntriesCounter = addCertificates(filterCreatedItems(allCertificates), truststoreCertificates);

        if (removedEntriesCounter > 0 || createdEntriesCounter > 0) {
            BkpsApp.restart();
        }
    }

    @Scheduled(cron = "${application.users.clean-service-cron}", zone = "UTC")
    public void cleanRemovedCertificates() {
        final Instant removedDate = Instant.now().minus(cleanRemovedAfterDays, ChronoUnit.DAYS);
        final List<DynamicCertificate> foundEntities = dynamicCertificateRepository
            .findAll(dynamicCertificateRepository.getRemovedByDate(removedDate));
        dynamicCertificateRepository.deleteAll(foundEntities);
    }

    private int addCertificates(List<DynamicCertificate> newCerts,
                                List<TruststoreCertificateEntryData> truststoreCertificates) {
        int entriesCounter = addMissingCertsToTruststore(newCerts, truststoreCertificates);
        if (entriesCounter > 0) {
            log.info("Service will be restarted - detected new certificates: {}", entriesCounter);
        }
        return entriesCounter;
    }

    private int removeCertificates(List<DynamicCertificate> removedCerts,
                                   List<TruststoreCertificateEntryData> truststoreCertificates) {
        int entriesCounter = removeExistingCertsFromTruststore(removedCerts, truststoreCertificates);
        if (entriesCounter > 0) {
            log.info("Service will be restarted - detected removed certificates: {}", entriesCounter);
        }
        return entriesCounter;
    }

    private List<DynamicCertificate> filterCreatedItems(List<DynamicCertificate> allCertificates) {
        return allCertificates.stream()
            .filter(DynamicCertificate::isNotRemoved)
            .collect(Collectors.toList());
    }

    private List<DynamicCertificate> filterRemovedItems(List<DynamicCertificate> allCertificates) {
        return allCertificates.stream()
            .filter(DynamicCertificate::isRemoved)
            .collect(Collectors.toList());
    }

    private List<TruststoreCertificateEntryData> getExistingCertsFromTruststore() {
        try {
            return trustManagerFactory.getCertificateInfoList();
        } catch (Exception e) {
            log.error("Failed to get certificate info list from truststore.", e);
            throw new BKPInternalServerException(ErrorCodeMap.FAILED_TO_FETCH_INFORMATION);
        }
    }

    private int addMissingCertsToTruststore(List<DynamicCertificate> newCerts,
                                            List<TruststoreCertificateEntryData> trustCerts) {
        AtomicInteger counter = new AtomicInteger(0);
        for (DynamicCertificate entity : newCerts) {

            boolean notExists = trustCerts
                .stream()
                .map(TruststoreCertificateEntryData::getFingerprint)
                .noneMatch(entity.getFingerprint()::equalsIgnoreCase);

            if (notExists) {
                try {
                    X509Certificate x509Certificate = CertificateManager.parseContent(
                        entity.getCertificate().getBytes(StandardCharsets.UTF_8)
                    );
                    trustManagerFactory.addEntry(x509Certificate, entity.getAlias());
                    counter.getAndIncrement();
                    log.info("Adding missing certificate to truststore: {}", entity.getAlias());
                } catch (Exception e) {
                    log.error("Failed to add certificate {} to truststore", entity.getAlias(), e);
                }
            }
        }
        return counter.get();
    }

    private int removeExistingCertsFromTruststore(List<DynamicCertificate> removedCerts,
                                                  List<TruststoreCertificateEntryData> trustCerts) {
        AtomicInteger counter = new AtomicInteger(0);
        for (DynamicCertificate entity : removedCerts) {
            trustCerts
                .stream()
                .filter(truststoreEntry -> truststoreEntry.getFingerprint().equalsIgnoreCase(entity.getFingerprint()))
                .forEach(existingEntry -> {
                    try {
                        trustManagerFactory.removeEntry(existingEntry.getAlias());
                        counter.getAndIncrement();
                        log.info("Removing certificate from truststore: {}", entity.getAlias());
                    } catch (Exception e) {
                        log.error("Failed to remove certificate {} from truststore", entity.getAlias(), e);
                    }
                });
        }
        return counter.get();
    }
}
