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
import com.intel.bkp.bkps.domain.SealingKey_;
import com.intel.bkp.bkps.repository.SealingKeyRepository;
import com.intel.bkp.core.security.ISecurityProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class SealingKeyRetentionService {

    private final SealingKeyRepository sealingKeyRepository;
    private final ISecurityProvider securityProvider;

    @Value("${service.data-retention.preserve-items}")
    private int preserveItems;

    @Value("${service.data-retention.sealing-key-threshold-days}")
    private int sealingKeyThreshold;

    @Async("taskExecutor")
    public void clean() {
        log.info("Starting sealing key data retention ...");
        Specification<SealingKey> spec = getSpecification(getNewest());

        sealingKeyRepository.findAll(spec)
            .forEach(sealingKey -> {
                if (securityProvider.existsSecurityObject(sealingKey.getGuid())) {
                    securityProvider.deleteSecurityObject(sealingKey.getGuid());
                }
                sealingKeyRepository.delete(sealingKey);
            });
        log.info("Finished sealing key data retention.");
    }

    private Specification<SealingKey> getSpecification(List<Long> lastIds) {
        return Specification.allOf(
            sealingKeyRepository.findAllNotEnabled(),
            sealingKeyRepository.getOlderOrEqualToTime(getTimeWithThreshold()),
            sealingKeyRepository.notIn(lastIds));
    }

    private List<Long> getNewest() {
        PageRequest topList = getPageRequest();
        Page<SealingKey> last = sealingKeyRepository.findAll(topList);
        return last.stream().map(SealingKey::getId).collect(Collectors.toList());
    }

    private PageRequest getPageRequest() {
        return PageRequest.of(0, preserveItems, Sort.Direction.DESC, SealingKey_.PROCESSED_DATE);
    }

    private Instant getTimeWithThreshold() {
        return Instant.now().minus(sealingKeyThreshold, ChronoUnit.DAYS);
    }
}
