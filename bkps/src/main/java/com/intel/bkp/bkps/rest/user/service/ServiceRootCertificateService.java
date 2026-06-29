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
import com.intel.bkp.bkps.domain.Authority;
import com.intel.bkp.bkps.domain.DynamicCertificate;
import com.intel.bkp.bkps.repository.DynamicCertificateRepository;
import com.intel.bkp.bkps.repository.UserRepository;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.user.model.dto.DynamicCertificateDTO;
import com.intel.bkp.bkps.rest.user.model.mapper.DynamicCertificateMapper;
import com.intel.bkp.bkps.rest.user.utils.RestartServerHelper;
import com.intel.bkp.bkps.security.X509TrustManagerManager;
import com.intel.bkp.bkps.utils.CertificateManager;
import com.intel.bkp.bkps.utils.DateMapper;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.core.exceptions.BKPNotFoundException;
import com.intel.bkp.core.helper.CertificateExistenceType;
import com.intel.bkp.core.helper.DynamicCertificateType;
import com.intel.bkp.core.helper.TruststoreCertificateEntryData;
import com.intel.bkp.core.utils.CustomErrorCode;
import com.intel.bkp.crypto.exceptions.X509CertificateParsingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.PrincipalUtil;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.intel.bkp.bkps.utils.CertificateManager.getCertificateFingerprint;
import static com.intel.bkp.bkps.utils.CertificateManager.parseContent;
import static com.intel.bkp.core.utils.ApplicationConstants.DATE_FORMAT;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(isolation = Isolation.SERIALIZABLE)
public class ServiceRootCertificateService {

    private final X509TrustManagerManager x509TrustManagerFactory;
    private final DynamicCertificateRepository dynamicCertificateRepository;
    private final DynamicCertificateMapper dynamicCertificateMapper;
    private final UserRepository userRepository;
    private final DateMapper dateMapper;

    public void rootCertificateImport(MultipartFile uploadedFile) {
        final byte[] sentData = getUploadContent(uploadedFile);
        final X509Certificate leafCertificate = getLeafCertificate(sentData);
        final String fingerprint = getCertificateFingerprint(leafCertificate);
        final Instant validUntil = leafCertificate.getNotAfter().toInstant();
        ensureFingerprintUniqueness(fingerprint);

        final String rawCertificateData = new String(sentData, StandardCharsets.UTF_8);
        final var entity = DynamicCertificate.createServerCert(fingerprint, validUntil, rawCertificateData);
        updateTrustStore(leafCertificate, entity.getAlias());
        dynamicCertificateRepository.save(entity);
        RestartServerHelper.restartServer();
        log.info("Saved root server certificate with fingerprint: {}", fingerprint);
    }

    public List<DynamicCertificateDTO> getAll() {
        final List<DynamicCertificateDTO> truststoreList = prepareDataFromTruststore();
        final List<DynamicCertificateDTO> databaseList = prepareDataFromDatabase();
        return matchCertificates(truststoreList, databaseList);
    }

    public void delete(String alias) {
        final DynamicCertificate existingEntity = dynamicCertificateRepository.findByAlias(alias)
            .orElseThrow(() -> new BKPNotFoundException(
                new CustomErrorCode(ErrorCodeMap.CERTIFICATE_FAILED_TO_REMOVE,
                    String.format(ErrorCodeMap.CERTIFICATE_FAILED_TO_REMOVE.getExternalMessage(), alias))));
        dynamicCertificateRepository.delete(existingEntity);
        try {
            if (x509TrustManagerFactory.exists(existingEntity.getAlias())) {
                x509TrustManagerFactory.removeEntry(existingEntity.getAlias());
                RestartServerHelper.restartServer();
            }
        } catch (Exception e) {
            log.error("Failed to remove entry from truststore", e);
        }
    }

    public boolean isAnyCertificateCloseToExpire(int daysThreshold) {
        return dynamicCertificateRepository.count(dynamicCertificateRepository.byCloseToExpire(daysThreshold)) > 0;
    }

    public List<DynamicCertificateDTO> getCloseToExpireCertificates(int daysThreshold) {
        return dynamicCertificateRepository
            .findAll(dynamicCertificateRepository.byCloseToExpire(daysThreshold))
            .stream()
            .map(entry -> {
                final DynamicCertificateDTO dto = dynamicCertificateMapper.toDto(entry);
                appendCertificateData(entry, dto);
                return dto;
            })
            .collect(Collectors.toList());
    }

    public boolean isAnyNotExpired(List<String> userFingerprints) {
        final List<DynamicCertificate> items = dynamicCertificateRepository
            .findAllByFingerprintInAndRemovedDateIsNull(userFingerprints);

        if (userFingerprints.size() > items.size()) {
            return true;
        } else {
            return items.stream().anyMatch(this::isStillValid);
        }
    }

    private byte[] getUploadContent(MultipartFile uploadedFile) {
        try {
            return uploadedFile.getBytes();
        } catch (IOException e) {
            throw new BKPBadRequestException(ErrorCodeMap.USER_INVALID_FILE_UPLOADED, e);
        }
    }

    private void updateTrustStore(X509Certificate leafCertificate, String alias) {
        try {
            x509TrustManagerFactory.addEntry(leafCertificate, alias);
        } catch (Exception e) {
            throw new BKPInternalServerException(ErrorCodeMap.SAVE_CERTIFICATE_IN_TRUSTSTORE_FAILED, e);
        }
    }

    private X509Certificate getLeafCertificate(byte[] sentData) {
        CertificateManager certificateManager = new CertificateManager();
        certificateManager.parseChain(sentData);
        return certificateManager.getLeafCertificate();
    }

    private void ensureFingerprintUniqueness(String fingerprint) {
        if (dynamicCertificateRepository.existsByFingerprint(fingerprint)) {
            throw new BKPBadRequestException(ErrorCodeMap.USER_DUPLICATED_FINGERPRINT);
        }
    }

    private List<DynamicCertificateDTO> prepareDataFromDatabase() {
        return dynamicCertificateRepository
            .findAll()
            .stream()
            .map(entry -> {
                final DynamicCertificateDTO dto = dynamicCertificateMapper.toDto(entry);
                appendCertificateData(entry, dto);
                return dto;
            })
            .collect(Collectors.toList());
    }

    private void appendCertificateData(DynamicCertificate entry, DynamicCertificateDTO dto) {
        try {
            final X509Certificate x509Certificate =
                parseContent(entry.getCertificate().getBytes(StandardCharsets.UTF_8));
            final Instant validUntilDate = Optional
                .ofNullable(entry.getValidUntil())
                .orElse(x509Certificate.getNotAfter().toInstant());
            dto.setValidUntil(dateMapper.asStringFormat(DATE_FORMAT, validUntilDate));
            dto.setSubject(PrincipalUtil.getSubjectX509Principal(x509Certificate).getName());
            dto.setExistenceType(CertificateExistenceType.DATABASE);
            userRepository.findOneWithAuthoritiesByFingerprint(dto.getFingerprint())
                .ifPresent(appUser -> {
                    getUserRoles(appUser).ifPresent(dto::setRole);
                    dto.setUserId(appUser.getId());
                });
        } catch (X509CertificateParsingException | CertificateEncodingException e) {
            log.error("Failed to generate certificate data", e);
        }
    }

    private static Optional<String> getUserRoles(AppUser appUser) {
        if (!appUser.getAuthorities().isEmpty()) {
            return Optional.of(appUser.getAuthorities().stream().map(Authority::getName)
                .collect(Collectors.joining(", ")));
        } else {
            return Optional.empty();
        }
    }

    private boolean isStillValid(DynamicCertificate entry) {
        try {
            final X509Certificate x509Certificate =
                parseContent(entry.getCertificate().getBytes(StandardCharsets.UTF_8));
            final Instant validUntilDate = Optional
                .ofNullable(entry.getValidUntil())
                .orElse(x509Certificate.getNotAfter().toInstant());
            return validUntilDate.isAfter(Instant.now());
        } catch (X509CertificateParsingException e) {
            log.error("Failed to generate certificate data", e);
            return true;
        }
    }

    private List<DynamicCertificateDTO> prepareDataFromTruststore() {
        List<DynamicCertificateDTO> list = new ArrayList<>();
        try {
            list.addAll(x509TrustManagerFactory.getCertificateInfoList()
                .stream()
                .map(this::processDataFromTruststore)
                .toList());
        } catch (KeyStoreException e) {
            log.error("Failed to read certificates from Truststore.", e);
        }
        return list;
    }

    private DynamicCertificateDTO processDataFromTruststore(TruststoreCertificateEntryData entry) {
        final DynamicCertificateDTO dto = new DynamicCertificateDTO();
        dto.setCreatedDate("-");
        dto.setAlias(entry.getAlias());
        dto.setSubject(entry.getSubject());
        dto.setValidUntil(
            dateMapper.asStringFormat(DATE_FORMAT, entry.getValidUntil())
        );
        dto.setFingerprint(entry.getFingerprint());
        dto.setCertificateType(DynamicCertificateType.SERVER);
        dto.setExistenceType(CertificateExistenceType.TRUSTSTORE);
        return dto;
    }

    private List<DynamicCertificateDTO> matchCertificates(List<DynamicCertificateDTO> truststoreList,
                                                          List<DynamicCertificateDTO> dbList) {
        HashMap<String, DynamicCertificateDTO> map = new HashMap<>();
        truststoreList.forEach(entry -> map.put(entry.getFingerprint(), entry));

        dbList.forEach(entry -> {
            final String uniqueKey = entry.getFingerprint();
            if (!map.containsKey(uniqueKey)) {
                map.put(uniqueKey, entry);
            } else {
                final DynamicCertificateDTO dto = map.get(uniqueKey);
                dto.setExistenceType(CertificateExistenceType.BOTH);
                dto.setCertificateType(entry.getCertificateType());
                dto.setCreatedDate(entry.getCreatedDate());
                dto.setRemovedDate(entry.getRemovedDate());
            }
        });

        return map
            .values()
            .stream()
            .sorted(Comparator.comparing(DynamicCertificateDTO::getCertificateType))
            .collect(Collectors.toList());
    }
}
