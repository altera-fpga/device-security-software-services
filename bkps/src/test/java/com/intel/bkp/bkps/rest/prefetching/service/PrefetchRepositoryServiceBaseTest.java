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

package com.intel.bkp.bkps.rest.prefetching.service;

import com.intel.bkp.bkps.attestation.mapping.CacheObjectMapper;
import com.intel.bkp.bkps.domain.PrefetchEntity;
import com.intel.bkp.bkps.domain.enumeration.PrefetchEntityType;
import com.intel.bkp.bkps.repository.PrefetchRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PrefetchRepositoryServiceBaseTest {

    private static final String PATH = "test/path";
    private static final Integer OBJ = 3;
    private static final String OBJ_ENCODED = "3";

    private static class PrefetchRepositoryServiceBaseTestImpl extends PrefetchRepositoryServiceBase<Integer> {

        PrefetchRepositoryServiceBaseTestImpl(PrefetchEntityType type, PrefetchRepository prefetchRepository,
                                              CacheObjectMapper<Integer> mapper) {
            super(type, prefetchRepository, mapper);
        }
    }

    private static final PrefetchEntityType ENTITY_TYPE = PrefetchEntityType.CRL;

    @Mock
    private PrefetchRepository prefetchRepository;
    @Mock
    private CacheObjectMapper<Integer> mapper;

    private PrefetchRepositoryServiceBaseTestImpl sut;

    @BeforeEach
    void prepareSut() {
        sut = new PrefetchRepositoryServiceBaseTestImpl(ENTITY_TYPE, prefetchRepository, mapper);
    }

    @Test
    void getMapper_Success() {
        // when-then
        assertEquals(mapper, sut.getMapper());
    }

    @Test
    void save_Success() {
        // given
        final var expectedEntity = new PrefetchEntity(PATH, OBJ_ENCODED, ENTITY_TYPE);
        when(mapper.encode(OBJ)).thenReturn(OBJ_ENCODED);

        // when
        sut.save(PATH, OBJ);

        // then
        verify(prefetchRepository).save(expectedEntity);
    }

    @Test
    void find_WhenEntityExists_Success() {
        // given
        final var entity = new PrefetchEntity(PATH, OBJ_ENCODED, ENTITY_TYPE);
        when(prefetchRepository.findByPathAndType(PATH, ENTITY_TYPE)).thenReturn(Optional.of(entity));
        when(mapper.decode(OBJ_ENCODED)).thenReturn(OBJ);

        // when
        final var result = sut.find(PATH);

        // then
        assertEquals(Optional.of(OBJ), result);
    }

    @Test
    void find_WhenEntityDoesNotExist_Success() {
        // given
        when(prefetchRepository.findByPathAndType(PATH, ENTITY_TYPE)).thenReturn(Optional.empty());

        // when
        final var result = sut.find(PATH);

        // then
        assertEquals(Optional.empty(), result);
    }
}
