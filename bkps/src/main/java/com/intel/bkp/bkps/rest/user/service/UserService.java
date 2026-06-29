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
import com.intel.bkp.bkps.exception.AppUserHasRoleAlreadyAssigned;
import com.intel.bkp.bkps.repository.UserRepository;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.user.model.mapper.AppUserMapper;
import com.intel.bkp.bkps.security.AuthorityType;
import com.intel.bkp.bkps.utils.CertificateManager;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.BKPNotFoundException;
import com.intel.bkp.core.helper.AppUserDTO;
import com.intel.bkp.core.helper.UserRoleManagementDTO;
import com.intel.bkp.crypto.exceptions.X509CertificateParsingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.intel.bkp.bkps.security.AuthorityType.ROLE_ADMIN;
import static com.intel.bkp.bkps.security.AuthorityType.ROLE_SUPER_ADMIN;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(isolation = Isolation.SERIALIZABLE)
public class UserService {

    private final UserRepository userRepository;
    private final AppUserMapper appUserMapper;
    private final DynamicCertificateService dynamicCertificateService;
    private final UserTokenService userTokenService;

    public String createUserInitial(String tempAccessToken, MultipartFile uploadedFile) {
        userTokenService.verifyTempAccessToken(tempAccessToken);
        return save(uploadedFile, true);
    }

    public String save(MultipartFile uploadedFile, boolean initial) {
        final String userCertificate = getUploadContent(uploadedFile);

        X509Certificate parsedCertificate = parseCertificate(userCertificate);
        final String fingerprint = CertificateManager.getCertificateFingerprint(parsedCertificate);
        final Instant validUntil = getValidUntil(parsedCertificate);

        final boolean existsInUsersTable = isFingerprintInUsersTable(fingerprint);
        final boolean existsInDynamicCertsTable = dynamicCertificateService.fingerprintExists(fingerprint);

        if (existsInUsersTable && existsInDynamicCertsTable) {
            throw new BKPBadRequestException(ErrorCodeMap.USER_DUPLICATED_FINGERPRINT);
        }

        dynamicCertificateService.verifyNotExistInTruststore(userCertificate);

        String login = getLoginFromExistingOrCreate(initial, fingerprint);

        if (!existsInDynamicCertsTable) {
            dynamicCertificateService.saveCertificateData(userCertificate, fingerprint, validUntil, login);
        }

        userTokenService.clearAccessToken();

        return userCertificate;
    }

    public List<AppUserDTO> getAll() {
        return userRepository.getAllWithAuthorities().stream().map(appUserMapper::toDto).collect(Collectors.toList());
    }

    public void delete(Long id) {
        final AppUser appUser = userRepository.findById(id)
            .orElseThrow(() -> new BKPNotFoundException(ErrorCodeMap.USER_NOT_FOUND));
        userRepository.delete(appUser);
        dynamicCertificateService.deleteDynamicCertForUser(appUser);
        userTokenService.refreshTempAccessToken();
    }

    public AppUserDTO roleSet(Long userId, UserRoleManagementDTO dto) {
        final AppUser appUser = getAppUser(userId);
        final Set<Authority> authorities = appUser.getAuthorities();
        verifyHasNoRole(authorities);

        verifyRoleExists(dto);
        final String role = dto.getRole();
        verifyUserCanSetRole(role);

        final Authority newRole = Authority.from(role);
        authorities.add(newRole);
        userRepository.save(appUser);

        if (ROLE_SUPER_ADMIN.name().equalsIgnoreCase(dto.getRole())) {
            userTokenService.clearAccessToken();
        }

        return appUserMapper.toDto(appUser);
    }

    public AppUserDTO roleUnset(Long userId, UserRoleManagementDTO dto) {
        final AppUser appUser = getAppUser(userId);
        verifyRoleExists(dto);
        final Authority newRole = Authority.from(dto.getRole());
        final Set<Authority> authorities = appUser.getAuthorities();
        authorities.remove(newRole);
        userRepository.save(appUser);
        return appUserMapper.toDto(appUser);
    }

    private String getLoginFromExistingOrCreate(boolean initial, String fingerprint) {
        return userRepository.findOneWithAuthoritiesByFingerprint(fingerprint).map(AppUser::getLogin)
            .orElse(saveUserData(initial, fingerprint));
    }

    private String saveUserData(boolean initial, String fingerprint) {
        AppUser appUser = new AppUser()
            .generateLogin()
            .assignDefaultRole(initial)
            .fingerprint(fingerprint);
        userRepository.save(appUser);
        log.info("Created new user: {}", appUser);
        return appUser.getLogin();
    }

    private String getUploadContent(MultipartFile uploadedFile) {
        try {
            return new String(uploadedFile.getBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new BKPBadRequestException(ErrorCodeMap.USER_INVALID_FILE_UPLOADED, e);
        }
    }

    private boolean isFingerprintInUsersTable(String fingerprint) {
        return userRepository.existsByFingerprint(fingerprint);
    }

    private void verifyHasNoRole(Set<Authority> authorities) {
        if (!authorities.isEmpty()) {
            throw new AppUserHasRoleAlreadyAssigned(authorities);
        }
    }

    private AppUser getAppUser(Long userId) {
        return userRepository
            .findOneWithAuthoritiesById(userId)
            .orElseThrow(() -> new BKPBadRequestException(ErrorCodeMap.USER_NOT_FOUND));
    }

    private void verifyRoleExists(UserRoleManagementDTO dto) {
        if (!AuthorityType.exists(dto.getRole())) {
            throw new BKPBadRequestException(ErrorCodeMap.USER_ROLE_NOT_VALID);
        }
    }

    private void verifyUserCanSetRole(String role) {
        Authentication authentication = getContextAuthentication();
        if (authentication == null) {
            throw new BKPBadRequestException(ErrorCodeMap.USER_ROLE_RESTRICTED);
        }
        final AuthorityType newRole = AuthorityType.findByName(role);
        final boolean isNotSuperAdmin = getAuthorities(authentication)
            .noneMatch(s -> s.equalsIgnoreCase(ROLE_SUPER_ADMIN.name()));
        final boolean isRestrictedRole = ROLE_SUPER_ADMIN == newRole || ROLE_ADMIN == newRole;
        if (isNotSuperAdmin && isRestrictedRole) {
            throw new BKPBadRequestException(ErrorCodeMap.USER_ROLE_RESTRICTED);
        }
    }

    Authentication getContextAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    private Stream<String> getAuthorities(Authentication authentication) {
        return authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority);
    }

    private X509Certificate parseCertificate(String userCertificate) {
        try {
            return CertificateManager.parseContent(userCertificate.getBytes(StandardCharsets.UTF_8));
        } catch (X509CertificateParsingException e) {
            throw new BKPBadRequestException(ErrorCodeMap.USER_INVALID_CERT_UPLOADED, e);
        }
    }

    private Instant getValidUntil(X509Certificate userCertificate) {
        return userCertificate.getNotAfter().toInstant();
    }
}
