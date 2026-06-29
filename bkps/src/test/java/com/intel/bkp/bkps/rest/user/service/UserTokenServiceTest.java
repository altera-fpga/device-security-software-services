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
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static com.intel.bkp.test.AssertionUtils.verifyExpectedErrorCode;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class UserTokenServiceTest {

    private static final String TEST_TOKEN = "testToken";

    @Mock
    private UserRepository userRepository;

    @Mock
    private ServiceRootCertificateService serviceRootCertificateService;

    @Mock
    private SharedVariableRepository sharedVariableRepository;

    @Mock
    private DateMapper dateMapper;

    @InjectMocks
    private UserTokenService sut;

    @BeforeEach
    void setUp() {
        prepareInjectedFields();
    }

    @Test
    void refreshTempAccessToken_Success() {
        // given
        mockAnySuperAdminActive(true, false);

        // when
        sut.refreshTempAccessToken();

        // then
        verify(sharedVariableRepository)
            .save(ArgumentMatchers.any(SharedVariable.class));
    }

    @Test
    void refreshTempAccessToken_WithAnySuperAdminActive_NotSaveAnything() {
        // given
        mockAnySuperAdminActive(false, true);

        // when
        sut.refreshTempAccessToken();

        // then
        verify(sharedVariableRepository, never())
            .save(ArgumentMatchers.any(SharedVariable.class));
    }

    @Test
    void refreshTempAccessToken_WithValidSharedVariable_NotSaveAnything() {
        // given
        mockAnySuperAdminActive(false, false);
        mockUserTokenVariable(true);

        // when
        sut.refreshTempAccessToken();

        // then
        verify(sharedVariableRepository, never())
            .save(ArgumentMatchers.any(SharedVariable.class));
    }

    @Test
    void refreshTempAccessToken_WithErrorSavingSharedVariable_LogsError() {
        // given
        mockAnySuperAdminActive(true, false);
        doThrow(DataIntegrityViolationException.class).when(sharedVariableRepository)
            .save(ArgumentMatchers.any(SharedVariable.class));

        // when
        sut.refreshTempAccessToken();

        // then
        verify(sharedVariableRepository)
            .save(ArgumentMatchers.any(SharedVariable.class));
    }

    @Test
    void verifyTempAccessToken_Success() {
        // given
        mockUserTokenVariable(true);

        // when-then
        assertDoesNotThrow(() -> sut.verifyTempAccessToken(TEST_TOKEN));
    }

    @Test
    void verifyTempAccessToken_WithInvalidToken_ThrowsException() {
        // given
        mockUserTokenVariable(true);

        // when-then
        final BKPBadRequestException result = assertThrows(BKPBadRequestException.class,
            () -> sut.verifyTempAccessToken("invalidToken"));

        // then
        verifyExpectedErrorCode(result, ErrorCodeMap.USER_INVALID_TEMP_TOKEN);

    }

    @Test
    void verifyTempAccessToken_WithEmptyToken_ThrowsException() {
        // given
        mockUserTokenVariable(false);
        String token = "token";

        // when-then
        final BKPBadRequestException result = assertThrows(BKPBadRequestException.class,
            () -> sut.verifyTempAccessToken(token));

        // then
        verifyExpectedErrorCode(result, ErrorCodeMap.USER_ALREADY_INITIALIZED);
    }

    @Test
    void clearAccessToken_Success() {
        // given
        mockUserTokenVariable(true);

        // when
        sut.clearAccessToken();

        // then
        verify(sharedVariableRepository).delete(any(SharedVariable.class));
    }

    @Test
    void clearAccessToken_WithNoToken_Success() {
        // given
        mockUserTokenVariable(false);

        // when
        sut.clearAccessToken();

        // then
        verify(sharedVariableRepository, never()).delete(any(SharedVariable.class));
    }

    private void mockAnySuperAdminActive(boolean isEmpty, boolean isAnyNotExpired) {
        List<AppUser> appUsers = new ArrayList<>();

        if (!isEmpty) {
            final AppUser user = new AppUser();
            user.setFingerprint("userFingerprint");
            user.setAuthorities(Set.of(Authority.from(AuthorityType.ROLE_SUPER_ADMIN.name())));
            appUsers.add(user);

            when(serviceRootCertificateService.isAnyNotExpired(anyList()))
                .thenReturn(isAnyNotExpired);
        }

        when(userRepository.getAllByAuthoritiesContaining(any(Authority.class)))
            .thenReturn(appUsers);
    }

    private void mockUserTokenVariable(boolean isSet) {
        final SharedVariable sharedVariable = SharedVariable
            .builder()
            .variableDate(Instant.now().plus(12, ChronoUnit.HOURS))
            .variableType(SharedVariableType.USER_TOKEN.name())
            .variableValue(TEST_TOKEN)
            .build();

        when(sharedVariableRepository.findByVariableType(SharedVariableType.USER_TOKEN.name()))
            .thenReturn(isSet ? Optional.of(sharedVariable) : Optional.empty());
    }

    private void prepareInjectedFields() {
        ReflectionTestUtils.setField(sut, "activeTokenHours", 12);
    }
}
