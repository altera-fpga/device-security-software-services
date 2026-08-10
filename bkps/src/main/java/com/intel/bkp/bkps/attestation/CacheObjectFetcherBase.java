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

package com.intel.bkp.bkps.attestation;

import com.intel.bkp.bkps.attestation.mapping.CacheObjectMapper;
import com.intel.bkp.bkps.connector.DpConnector;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.prefetching.service.IPrefetchRepositoryService;
import com.intel.bkp.core.exceptions.BKPRuntimeException;
import com.intel.bkp.core.properties.DistributionPoint;
import com.intel.bkp.core.utils.CustomErrorCode;
import lombok.extern.slf4j.Slf4j;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Optional;

@Slf4j
public abstract class CacheObjectFetcherBase<T> {

    private final IPrefetchRepositoryService<T> repositoryService;
    private final CacheObjectMapper<T> mapper;
    private final DpConnector connector;
    private final DistributionPoint distributionPoint;

    CacheObjectFetcherBase(IPrefetchRepositoryService<T> repositoryService, DpConnector connector, DistributionPoint distributionPoint) {
        this.repositoryService = repositoryService;
        this.mapper = repositoryService.getMapper();
        this.connector = connector;
        this.distributionPoint = distributionPoint;
    }

    abstract boolean isValid(T obj);

    public Optional<T> fetch(String url) {
        String validUrl = validate(url);
        return findValidInCache(validUrl)
            .or(() -> downloadAndSaveInCache(validUrl));
    }

    public Optional<T> fetchSkipCache(String url) {
        String validUrl = validate(url);
        findValidInCache(validUrl).ifPresent(data ->
            log.debug("Found valid data in cache, but fresh content shall be retrieved from url: {}", validUrl));
        return downloadAndSaveInCache(validUrl);
    }

    private String validate(String url) {
        try {
            URL originalUrl = new URL(url);
            String originalDomain = originalUrl.getProtocol() + "://" + originalUrl.getAuthority();
            URL expectedUrl = new URL(distributionPoint.getMainPath());
            String expectedDomain = expectedUrl.getProtocol() + "://" + expectedUrl.getAuthority();
            String validUrl = url;
            // Replace only if the domains are different
            if (!originalDomain.equals(expectedDomain)) {
                validUrl = originalUrl.toString().replaceFirst(originalDomain, expectedDomain);
            }
            return validUrl;
        } catch (MalformedURLException e) {
            throw new BKPRuntimeException(new CustomErrorCode(ErrorCodeMap.MALFORMED_URL_PATH,
                String.format(ErrorCodeMap.MALFORMED_URL_PATH.getExternalMessage(), url)));
        }
    }

    private Optional<T> findValidInCache(String url) {
        return repositoryService.find(url)
            .filter(this::isValid);
    }

    private Optional<T> downloadAndSaveInCache(String url) {
        return download(url).map(obj -> saveInCache(url, obj));
    }

    private Optional<T> download(String url) {
        log.debug("Downloading from url: {}", url);
        return connector.tryGetBytes(url).flatMap(mapper::parse);
    }

    private T saveInCache(String url, T obj) {
        repositoryService.save(url, obj);
        return obj;
    }
}
