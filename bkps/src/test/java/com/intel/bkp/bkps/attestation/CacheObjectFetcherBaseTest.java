/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2024 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.bkps.attestation;

import com.intel.bkp.bkps.attestation.mapping.CacheObjectMapper;
import com.intel.bkp.bkps.connector.DpConnector;
import com.intel.bkp.bkps.rest.prefetching.service.IPrefetchRepositoryService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Objects;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CacheObjectFetcherBaseTest {

    private static final Integer VALID_OBJ = 3;
    private static final Integer INVALID_OBJ = -7;
    private static final byte[] OBJ_BYTES = {0x01, 0x02};
    private static final String PATH = "path";

    private static class CacheObjectFetcherBaseTestImpl extends CacheObjectFetcherBase<Integer> {

        CacheObjectFetcherBaseTestImpl(IPrefetchRepositoryService<Integer> repositoryService,
                                       DpConnector connector) {
            super(repositoryService, connector);
        }

        @Override
        boolean isValid(Integer obj) {
            return Objects.equals(obj, VALID_OBJ);
        }
    }

    @Mock
    private IPrefetchRepositoryService<Integer> prefetchRepositoryService;

    @Mock
    private CacheObjectMapper<Integer> mapper;

    @Mock
    private DpConnector dpConnector;

    private CacheObjectFetcherBaseTestImpl sut;

    @BeforeEach
    void prepareSut() {
        when(prefetchRepositoryService.getMapper()).thenReturn(mapper);
        sut = new CacheObjectFetcherBaseTestImpl(prefetchRepositoryService, dpConnector);
    }

    @Test
    void fetch_WhenNoObjCached_DownloadsAndSavesInCacheEvenIfNotValid() {
        // given
        when(prefetchRepositoryService.find(PATH)).thenReturn(Optional.empty());
        when(dpConnector.tryGetBytes(PATH)).thenReturn(Optional.of(OBJ_BYTES));
        final Optional<Integer> expected = Optional.of(INVALID_OBJ);
        when(mapper.parse(OBJ_BYTES)).thenReturn(expected);

        // when
        final var result = sut.fetch(PATH);

        // then
        assertEquals(expected, result);
        verify(prefetchRepositoryService).save(PATH, INVALID_OBJ);
    }

    @Test
    void fetch_WhenObjCachedButNotValid_DownloadsAndSavesInCache() {
        // given
        when(prefetchRepositoryService.find(PATH)).thenReturn(Optional.of(INVALID_OBJ));
        when(dpConnector.tryGetBytes(PATH)).thenReturn(Optional.of(OBJ_BYTES));
        final Optional<Integer> expected = Optional.of(VALID_OBJ);
        when(mapper.parse(OBJ_BYTES)).thenReturn(expected);

        // when
        final var result = sut.fetch(PATH);

        // then
        assertEquals(expected, result);
        verify(prefetchRepositoryService).save(PATH, VALID_OBJ);
    }

    @Test
    void fetch_WhenObjCachedAndValid_ReturnsCachedWithoutDownloading() {
        // given
        final Optional<Integer> expected = Optional.of(VALID_OBJ);
        when(prefetchRepositoryService.find(PATH)).thenReturn(expected);

        // when
        final var result = sut.fetch(PATH);

        // then
        assertEquals(expected, result);
        verifyNoInteractions(dpConnector);
        verify(prefetchRepositoryService, never()).save(any(), any());
    }

}
