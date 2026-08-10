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

import com.intel.bkp.bkps.domain.SealingKey;
import com.intel.bkp.bkps.repository.SealingKeyRepository;
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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
public class SealingKeyRetentionServiceTest {

    private final Specification<SealingKey> specSealingKey = (root, query, criteriaBuilder) -> null;

    @Mock
    private ISecurityProvider securityProvider;

    @Mock
    private SealingKeyRepository sealingKeyRepository;

    @InjectMocks
    private SealingKeyRetentionService sut;


    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(sut, "preserveItems", 1);
        ReflectionTestUtils.setField(sut, "sealingKeyThreshold", 1);
    }

    @Test
    void clean_WithEmptyList_NoDelete() {
        // given
        when(sealingKeyRepository.findAll(any(PageRequest.class)))
            .thenReturn(Page.empty());
        final Specification<SealingKey> localSpec = any();
        when(sealingKeyRepository.findAll(localSpec))
            .thenReturn(prepareSealingKeyResponse(true));

        when(sealingKeyRepository.findAllNotEnabled()).thenReturn(specSealingKey);
        when(sealingKeyRepository.getOlderOrEqualToTime(any())).thenReturn(specSealingKey);

        // when
        sut.clean();

        // then
        verify(sealingKeyRepository).findAllNotEnabled();
        verify(sealingKeyRepository).getOlderOrEqualToTime(any());
        verify(sealingKeyRepository, never())
            .delete(any(SealingKey.class));
    }

    @Test
    void clean_WithPopulatedList_Deletes() {
        // given
        when(sealingKeyRepository.findAll(any(PageRequest.class)))
            .thenReturn(Page.empty());
        final Specification<SealingKey> localSpec = any();
        when(sealingKeyRepository.findAll(localSpec))
            .thenReturn(prepareSealingKeyResponse(false));

        when(sealingKeyRepository.findAllNotEnabled()).thenReturn(specSealingKey);
        when(sealingKeyRepository.getOlderOrEqualToTime(any())).thenReturn(specSealingKey);

        when(securityProvider.existsSecurityObject(anyString())).thenReturn(true);

        // when
        sut.clean();

        // then
        verify(sealingKeyRepository).findAllNotEnabled();
        verify(sealingKeyRepository).getOlderOrEqualToTime(any());
        verify(sealingKeyRepository, times(2))
            .delete(any(SealingKey.class));
    }

    private ArrayList<SealingKey> prepareSealingKeyResponse(boolean isEmpty) {
        final ArrayList<SealingKey> list = new ArrayList<>();
        if (!isEmpty) {
            final SealingKey entity = new SealingKey();
            entity.setProcessedDate(Instant.now().minus(5, ChronoUnit.DAYS));
            entity.setGuid(UUID.randomUUID().toString());
            list.add(entity);
            final SealingKey entity2 = new SealingKey();
            entity.setProcessedDate(Instant.now().minus(2, ChronoUnit.HOURS));
            entity.setGuid(UUID.randomUUID().toString());
            list.add(entity2);
            return list;
        }
        return list;
    }
}
