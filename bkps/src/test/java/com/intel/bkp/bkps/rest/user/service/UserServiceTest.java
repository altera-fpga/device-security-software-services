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
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.BKPNotFoundException;
import com.intel.bkp.core.helper.AppUserDTO;
import com.intel.bkp.core.helper.UserRoleManagementDTO;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.test.CertificateUtils;
import com.intel.bkp.test.KeyGenUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.crypto.x509.utils.X509CertificateUtils.toPem;
import static com.intel.bkp.test.AssertionUtils.verifyExpectedErrorCode;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private AppUserMapper appUserMapper;

    @Mock
    private MultipartFile uploadedFile;

    @Mock
    private DynamicCertificateService dynamicCertificateService;

    @Mock
    private UserTokenService userTokenService;

    @Mock
    private AppUser appUser;

    @Mock
    private AnonymousAuthenticationToken authentication;

    @InjectMocks
    private UserService sut;

    private static final Long USER_ID = 10L;
    private static final String USER_TOKEN = "APP_TOKEN";

    @Test
    void save_WithNonInitialUser_Success() throws Exception {
        // given
        mockUploadedKeyCert();

        // when
        final String userCertificate = sut.save(uploadedFile, false);

        // then
        assertNotNull(userCertificate);
        verify(userRepository).save(any());
        verify(dynamicCertificateService).saveCertificateData(anyString(), anyString(), any(), anyString());
    }

    @Test
    void save_WithNonInitialUser_WithExistingFingerprint_ThrowsException() throws Exception {
        // given
        mockUploadedKeyCert();
        when(dynamicCertificateService.fingerprintExists(anyString()))
            .thenReturn(true);
        when(userRepository.existsByFingerprint(anyString()))
            .thenReturn(true);

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.save(uploadedFile, false)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.USER_DUPLICATED_FINGERPRINT);
    }

    @Test
    void save_WithNonInitialUser_WithNullUploadedFile_ThrowsException() throws Exception {
        // given
        when(uploadedFile.getBytes()).thenThrow(new IOException());

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.save(uploadedFile, false)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.USER_INVALID_FILE_UPLOADED);
    }

    @Test
    void createUserInitial_WithInitializedDatabase_Success() throws Exception {
        // given
        final KeyPair keyPair = KeyGenUtils.genRsa1024();
        mockUserModeCertificateUpload(keyPair);

        // when
        final String userCertificate = sut.createUserInitial(USER_TOKEN, uploadedFile);

        // then
        assertNotNull(userCertificate);
        verify(userRepository).save(any());
        verify(dynamicCertificateService).saveCertificateData(anyString(), anyString(), any(), anyString());
    }

    @Test
    void createUserInitial_WithInitializedDatabase_ThrowsException() {
        // given
        doThrow(new BKPBadRequestException(ErrorCodeMap.USER_ALREADY_INITIALIZED))
            .when(userTokenService)
            .verifyTempAccessToken(anyString());

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.createUserInitial(USER_TOKEN, uploadedFile)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.USER_ALREADY_INITIALIZED);
    }

    @Test
    void getAll_Success() {
        // given
        final ArrayList<AppUser> currentUserList = new ArrayList<>();
        currentUserList.add(new AppUser()
            .generateLogin()
            .assignDefaultRole(true)
            .fingerprint("testFingerprint"));
        when(userRepository.getAllWithAuthorities()).thenReturn(currentUserList);

        when(appUserMapper.toDto(any())).thenReturn(new AppUserDTO());

        // when
        final List<AppUserDTO> usersList = sut.getAll();

        // then
        assertEquals(currentUserList.size(), usersList.size());
    }

    @Test
    void delete_WithExistingUser_Success() {
        // given
        mockUser();

        // when
        sut.delete(USER_ID);

        // then
        verify(userRepository).delete(any());
        verify(dynamicCertificateService).deleteDynamicCertForUser(any(AppUser.class));
    }

    @Test
    void delete_WithNotExistingUser_ThrowsException() {
        // given
        when(userRepository.findById(USER_ID)).thenReturn(Optional.empty());

        // when-then
        final BKPNotFoundException exception = assertThrows(BKPNotFoundException.class,
            () -> sut.delete(USER_ID)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.USER_NOT_FOUND);
    }

    @Test
    void delete_WithExistingUser_WithErrorInX509TrustManager_NotRestartService() {
        // given
        mockUser();

        // when
        sut.delete(USER_ID);

        // then
        verify(userRepository).delete(any());
        verify(dynamicCertificateService).deleteDynamicCertForUser(any(AppUser.class));
    }

    @Test
    void delete_WithExistingUser_WithUniqueSuperAdminAsLastUser_Success() {
        // given
        mockUser();

        // when
        sut.delete(USER_ID);

        // then
        verify(userRepository).delete(any());
        verify(dynamicCertificateService).deleteDynamicCertForUser(any(AppUser.class));
    }

    @Test
    void roleSet_Success() {
        // given
        UserRoleManagementDTO roleManagementDTO = prepareRequestDTO(AuthorityType.ROLE_SUPER_ADMIN);
        mockExistingAppUserNoRole();
        UserService sutSpy = spy(sut);
        when(sutSpy.getContextAuthentication()).thenReturn(authentication);
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add(new SimpleGrantedAuthority(AuthorityType.ROLE_SUPER_ADMIN.name()));
        when(authentication.getAuthorities()).thenReturn(grantedAuthorities);

        // when
        sutSpy.roleSet(USER_ID, roleManagementDTO);

        // then
        verify(userRepository).save(any());
        verify(appUserMapper).toDto(any());
    }

    @Test
    void roleSet_WithNotAuthenticatedUser_ThrowsException() {
        // given
        UserRoleManagementDTO roleManagementDTO = prepareRequestDTO(AuthorityType.ROLE_SUPER_ADMIN);
        mockExistingAppUserNoRole();

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.roleSet(USER_ID, roleManagementDTO));
        assertEquals(ErrorCodeMap.USER_ROLE_RESTRICTED.getExternalMessage(), exception.getMessage());
    }

    @Test
    void roleSet_WithAuthenticatedUser_WithoutSuperAdminAccount_ThrowsException() {
        // given
        UserRoleManagementDTO roleManagementDTO = prepareRequestDTO(AuthorityType.ROLE_SUPER_ADMIN);
        mockExistingAppUserNoRole();
        UserService sutSpy = spy(sut);
        when(sutSpy.getContextAuthentication()).thenReturn(authentication);
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add(new SimpleGrantedAuthority(AuthorityType.ROLE_ADMIN.name()));
        when(authentication.getAuthorities()).thenReturn(grantedAuthorities);

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sutSpy.roleSet(USER_ID, roleManagementDTO));
        assertEquals(ErrorCodeMap.USER_ROLE_RESTRICTED.getExternalMessage(), exception.getMessage());
    }

    @Test
    void roleSet_WithNotValidRole_ThrowsException() {
        // given
        UserRoleManagementDTO roleManagementDTO = new UserRoleManagementDTO();
        roleManagementDTO.setRole("NotValidRole");
        mockExistingAppUserNoRole();

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.roleSet(USER_ID, roleManagementDTO)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.USER_ROLE_NOT_VALID);
    }

    @Test
    void roleSet_WithNoUserExists_ThrowsException() {
        // given
        UserRoleManagementDTO roleManagementDTO = prepareRequestDTO(AuthorityType.ROLE_SUPER_ADMIN);
        when(userRepository.findOneWithAuthoritiesById(USER_ID)).thenReturn(Optional.empty());

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.roleSet(USER_ID, roleManagementDTO)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.USER_NOT_FOUND);
    }

    @Test
    void roleSet_WithUserAlreadyHasRole_ThrowsException() {
        // given
        UserRoleManagementDTO roleManagementDTO = prepareRequestDTO(AuthorityType.ROLE_ADMIN);
        mockExistingAppUser(AuthorityType.ROLE_SUPER_ADMIN);

        // when
        assertThrows(AppUserHasRoleAlreadyAssigned.class, () -> sut.roleSet(USER_ID, roleManagementDTO));
    }

    @Test
    void roleUnset_Success() {
        // given
        UserRoleManagementDTO roleManagementDTO = prepareRequestDTO(AuthorityType.ROLE_SUPER_ADMIN);
        mockExistingAppUser(AuthorityType.ROLE_ADMIN);

        // when
        sut.roleUnset(USER_ID, roleManagementDTO);

        // then
        verify(userRepository).save(any());
        verify(appUserMapper).toDto(any());
    }

    private void mockUserModeCertificateUpload(KeyPair keyPair) throws IOException, CertificateEncodingException {
        when(uploadedFile.getBytes()).thenReturn(
                toPem(CertificateUtils.generateCertificate(keyPair, CryptoConstants.SHA384_WITH_RSA)).getBytes()
        );
    }

    private void mockExistingAppUser(AuthorityType authorityType) {
        when(userRepository.findOneWithAuthoritiesById(USER_ID)).thenReturn(Optional.of(appUser));
        final HashSet<Authority> authorities = new HashSet<>();
        if (authorityType != null) {
            authorities.add(Authority.from(authorityType.name()));
        }
        when(appUser.getAuthorities()).thenReturn(authorities);
    }

    private void mockExistingAppUserNoRole() {
        when(userRepository.findOneWithAuthoritiesById(USER_ID)).thenReturn(Optional.of(appUser));
        when(appUser.getAuthorities()).thenReturn(new HashSet<>());
    }

    private UserRoleManagementDTO prepareRequestDTO(AuthorityType authorityType) {
        UserRoleManagementDTO roleManagementDTO = new UserRoleManagementDTO();
        roleManagementDTO.setRole(authorityType.name());
        return roleManagementDTO;
    }

    private void mockUploadedKeyCert() throws Exception {
        final KeyPair keyPair = KeyGenUtils.genEc256();
        String hashAlg = CryptoConstants.SHA384_WITH_ECDSA;
        final byte[] data = toPem(CertificateUtils.generateCertificate(keyPair, hashAlg)).getBytes();
        when(uploadedFile.getBytes()).thenReturn(data);
    }

    private void mockUser() {
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(appUser));
    }
}
