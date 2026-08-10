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
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;

import static lombok.AccessLevel.PROTECTED;
import static lombok.AccessLevel.PUBLIC;

@Slf4j
@RequiredArgsConstructor
public abstract class PrefetchRepositoryServiceBase<T> implements IPrefetchRepositoryService<T> {

    @Getter(PROTECTED)
    private final PrefetchEntityType type;
    @Getter(PROTECTED)
    private final PrefetchRepository prefetchRepository;
    @Getter(PUBLIC)
    private final CacheObjectMapper<T> mapper;

    @Override
    public void save(String path, T obj) {
        prefetchRepository.save(new PrefetchEntity(path, mapper.encode(obj), type));
    }

    @Override
    public Optional<T> find(String path) {
        log.debug("Looking for {} in DB: {}", type, path);
        return prefetchRepository.findByPathAndType(path, type)
            .map(PrefetchEntity::getContent)
            .map(mapper::decode);
    }
}
