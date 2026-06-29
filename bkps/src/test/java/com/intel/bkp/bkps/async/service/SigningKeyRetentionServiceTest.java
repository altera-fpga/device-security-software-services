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

import com.intel.bkp.bkps.domain.SigningKeyEntity;
import com.intel.bkp.bkps.domain.enumeration.SigningKeyStatus;
import com.intel.bkp.bkps.repository.SigningKeyRepository;
import com.intel.bkp.core.security.ISecurityProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.UUID;

import static com.intel.bkp.test.RandomUtils.generateRandomLong;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
public class SigningKeyRetentionServiceTest {

    private final Specification<SigningKeyEntity> spec = (root, query, criteriaBuilder) -> null;

    @Mock
    private ISecurityProvider securityService;

    @Mock
    private SigningKeyRepository signingKeyRepository;

    @InjectMocks
    private SigningKeyRetentionService sut;


    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(sut, "preserveItems", 1);
        ReflectionTestUtils.setField(sut, "signingKeyThreshold", 1);
    }

    @Test
    void clean_WithEmptyList_DoNothing() {
        // given
        when(signingKeyRepository.findAll(any(PageRequest.class)))
            .thenReturn(Page.empty());
        final Specification<SigningKeyEntity> signingKeySpec = any();
        when(signingKeyRepository.findAll(signingKeySpec))
            .thenReturn(prepareSigningKeyResponse(true));

        when(signingKeyRepository.findAllNotEnabled()).thenReturn(spec);
        when(signingKeyRepository.getOlderOrEqualToTime(any())).thenReturn(spec);

        // when
        sut.clean();

        // then
        verify(signingKeyRepository).findAllNotEnabled();
        verify(signingKeyRepository).getOlderOrEqualToTime(any());
        verify(signingKeyRepository, never())
            .delete(any(SigningKeyEntity.class));
    }

    @Test
    void clean_WithPopulatedList_Deletes() {
        // given
        when(signingKeyRepository.findAll(any(PageRequest.class)))
            .thenReturn(Page.empty());
        final Specification<SigningKeyEntity> signingKeySpec = any();
        when(signingKeyRepository.findAll(signingKeySpec))
            .thenReturn(prepareSigningKeyResponse(false));

        when(signingKeyRepository.findAllNotEnabled()).thenReturn(spec);
        when(signingKeyRepository.getOlderOrEqualToTime(any())).thenReturn(spec);

        when(securityService.existsSecurityObject(anyString())).thenReturn(true);

        // when
        sut.clean();

        // then
        verify(signingKeyRepository).findAllNotEnabled();
        verify(signingKeyRepository).getOlderOrEqualToTime(any());
        verify(signingKeyRepository, times(2))
            .delete(any(SigningKeyEntity.class));
    }

    private ArrayList<SigningKeyEntity> prepareSigningKeyResponse(boolean isEmpty) {
        final ArrayList<SigningKeyEntity> list = new ArrayList<>();
        if (!isEmpty) {
            list.add(new SigningKeyEntity()
                .id(generateRandomLong())
                .name(UUID.randomUUID().toString())
                .status(SigningKeyStatus.DISABLED)
                .fingerprint(UUID.randomUUID().toString()));
            list.add(new SigningKeyEntity()
                .id(generateRandomLong())
                .name(UUID.randomUUID().toString())
                .status(SigningKeyStatus.DISABLED)
                .fingerprint(UUID.randomUUID().toString()));
        }
        return list;
    }
}
