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

package com.intel.bkp.bkps.rest.health.service;

import com.intel.bkp.bkps.rest.health.checker.DatabaseCheckerService;
import com.intel.bkp.bkps.rest.health.checker.ICheckerService;
import com.intel.bkp.bkps.rest.health.checker.SecurityProviderCheckerService;
import com.intel.bkp.bkps.rest.health.model.HealthResponse;
import com.intel.bkp.bkps.rest.health.model.HealthServiceStatus;
import com.intel.bkp.bkps.rest.health.model.HealthStatus;
import com.intel.bkp.bkps.rest.health.model.HealthTypes;
import com.intel.bkp.bkps.rest.health.model.ResourceType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class HealthService {

    private final ApplicationContext context;
    private final DatabaseCheckerService databaseChecker;
    private final SecurityProviderCheckerService securityProviderChecker;

    @Value("${spring.application.name}")
    private String name;
    @Value("${info.project.version}")
    private String version;

    public HealthResponse check(HealthTypes type) {
        if (HealthTypes.SLA == type) {
            return slaCheck();
        } else {
            return shallowCheck();
        }
    }

    public HttpStatus statusCheck(Optional<ResourceType> resourceTypeOptional) {
        return resourceTypeOptional
            .map(this::detailedStatusCheck)
            .orElseGet(this::overallStatusCheck);
    }

    private HttpStatus detailedStatusCheck(ResourceType resourceType) {
        try {
            HealthServiceStatus hsStatus = buildCheckersMap().get(resourceType).check();
            if (HealthStatus.OK == hsStatus.getStatus()) {
                return HttpStatus.OK;
            }
        } catch (Exception ex) {
            log.error("Failed to check resource: " + resourceType.name());
            return HttpStatus.BAD_REQUEST;
        }
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }

    private HttpStatus overallStatusCheck() {
        boolean isOk = checkConnections()
            .stream()
            .allMatch(s -> HealthStatus.OK == s.getStatus());

        return (isOk) ? HttpStatus.OK : HttpStatus.INTERNAL_SERVER_ERROR;
    }

    private HealthResponse shallowCheck() {
        return getBasicHealthResponse();
    }

    private HealthResponse slaCheck() {
        Environment env = context.getEnvironment();
        return getBasicHealthResponse()
            .currentSetting(String.join(",", env.getActiveProfiles()))
            .items(checkConnections());
    }

    private HealthResponse getBasicHealthResponse() {
        return new HealthResponse()
            .version(version)
            .name(name);
    }

    private List<HealthServiceStatus> checkConnections() {
        List<HealthServiceStatus> list = new ArrayList<>();
        list.add(databaseChecker.check());
        list.add(securityProviderChecker.check());
        return list;
    }

    private Map<ResourceType, ICheckerService> buildCheckersMap() {
        EnumMap<ResourceType, ICheckerService> map = new EnumMap<>(ResourceType.class);
        map.put(DatabaseCheckerService.NAME, databaseChecker);
        map.put(SecurityProviderCheckerService.NAME, securityProviderChecker);
        return map;
    }
}
