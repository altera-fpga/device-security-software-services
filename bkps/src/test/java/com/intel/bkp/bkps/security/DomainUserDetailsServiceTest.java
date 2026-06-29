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

package com.intel.bkp.bkps.security;

import com.intel.bkp.bkps.domain.AppUser;
import com.intel.bkp.bkps.domain.Authority;
import com.intel.bkp.bkps.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class DomainUserDetailsServiceTest {

    @Mock
    private UserRepository userRepository;

    private DomainUserDetailsService sut;

    @BeforeEach
    void setUp() {
        sut = new DomainUserDetailsService(userRepository);
    }

    @Test
    void loadUserByUsername_Success() {
        // given
        String testEntry = "tEstHashCode";
        String testFilteredEntry = testEntry.toLowerCase();
        AppUser user = new AppUser();
        user.setLogin("test");
        user.setFingerprint(testFilteredEntry);
        user.setId(1L);
        Set<Authority> authorities = new HashSet<>();
        user.setAuthorities(authorities);
        when(userRepository.findOneWithAuthoritiesByFingerprint(testFilteredEntry))
            .thenReturn(Optional.of(user));

        // when
        assertInstanceOf(UserDetails.class, sut.loadUserByUsername(testEntry));
    }

    @Test
    void loadUserByUsername_ThrowsException() {
        // given
        String testEntry = "tEstHashCode";
        String testFilteredEntry = testEntry.toLowerCase();
        when(userRepository.findOneWithAuthoritiesByFingerprint(testFilteredEntry))
            .thenReturn(Optional.empty());

        // when
        assertThrows(UsernameNotFoundException.class, () -> sut.loadUserByUsername(testEntry));
    }
}
