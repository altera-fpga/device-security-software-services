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
import com.intel.bkp.bkps.domain.SharedVariable;
import com.intel.bkp.bkps.domain.enumeration.SharedVariableType;
import com.intel.bkp.bkps.repository.SharedVariableRepository;
import com.intel.bkp.bkps.repository.UserRepository;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.security.AuthorityType;
import com.intel.bkp.bkps.utils.DateMapper;
import com.intel.bkp.bkps.utils.MdcHelper;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.utils.SecurityLogType;
import com.intel.bkp.crypto.CryptoUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserTokenService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final UserRepository userRepository;
    private final ServiceRootCertificateService serviceRootCertificateService;
    private final SharedVariableRepository sharedVariableRepository;
    private final DateMapper dateMapper;

    @Value("${application.users.active-token-hours}")
    private int activeTokenHours;

    @Transactional
    public void refreshTempAccessToken() {
        if (isAnySuperAdminActive()) {
            return;
        }

        final SharedVariable sharedVariable = getVariable(SharedVariableType.USER_TOKEN);

        if (isVariableValid(sharedVariable)) {
            logActiveAccessToken(sharedVariable);
            return;
        }

        generateAccessToken(sharedVariable);
        final boolean succeeded = updateVariable(sharedVariable);
        if (succeeded) {
            logActiveAccessToken(sharedVariable);
        }
    }

    public void verifyTempAccessToken(String token) {
        final String value = sharedVariableRepository.findByVariableType(SharedVariableType.USER_TOKEN.name())
            .map(SharedVariable::getVariableValue)
            .orElseThrow(() -> new BKPBadRequestException(ErrorCodeMap.USER_ALREADY_INITIALIZED));

        if (!value.equalsIgnoreCase(token)) {
            log.error("Token expected: {} and provided: {}.", value, token);
            throw new BKPBadRequestException(ErrorCodeMap.USER_INVALID_TEMP_TOKEN);
        }
    }

    @Transactional
    public void clearAccessToken() {
        log.info("Clearing Access Token");
        sharedVariableRepository.findByVariableType(SharedVariableType.USER_TOKEN.name())
            .ifPresent(sharedVariableRepository::delete);
    }

    private boolean isAnySuperAdminActive() {
        final List<AppUser> users = userRepository.getAllByAuthoritiesContaining(
            Authority.from(AuthorityType.ROLE_SUPER_ADMIN.name())
        );
        return !users.isEmpty() && serviceRootCertificateService
            .isAnyNotExpired(users.stream().map(AppUser::getFingerprint).collect(Collectors.toList()));
    }

    private void logActiveAccessToken(SharedVariable sharedVariable) {
        MdcHelper.addSecurityTag(SecurityLogType.SECURITY_AUTH);
        log.info("Temporary user access token: {} valid until: {}", sharedVariable.getVariableValue(),
            dateMapper.asString(sharedVariable.getVariableDate()));
        MdcHelper.removeSecurityTag();
    }

    private void generateAccessToken(SharedVariable sharedVariable) {
        log.debug("Generating new user access token.");
        byte[] tokenRaw = new byte[512];
        SECURE_RANDOM.nextBytes(tokenRaw);
        sharedVariable.setVariableValue(CryptoUtils.generateSha256Fingerprint(tokenRaw));
        sharedVariable.setVariableDate(Instant.now().plus(activeTokenHours, ChronoUnit.HOURS));
    }

    private boolean isVariableValid(SharedVariable sharedVariable) {
        return sharedVariable.getVariableDate() != null
            && Instant.now().isBefore(sharedVariable.getVariableDate())
            && StringUtils.isNotBlank(sharedVariable.getVariableValue());
    }

    private SharedVariable getVariable(SharedVariableType variableType) {
        final String name = variableType.name();
        return sharedVariableRepository
            .findByVariableType(name)
            .orElse(SharedVariable.builder().variableType(name).build());
    }

    private boolean updateVariable(SharedVariable sharedVariable) {
        try {
            sharedVariableRepository.save(sharedVariable);
            return true;
        } catch (Exception e) {
            log.info("Token was updated by different instance.");
            return false;
        }
    }
}
