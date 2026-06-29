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
import com.intel.bkp.bkps.rest.health.checker.SecurityProviderCheckerService;
import com.intel.bkp.bkps.rest.health.model.HealthResponse;
import com.intel.bkp.bkps.rest.health.model.HealthServiceStatus;
import com.intel.bkp.bkps.rest.health.model.HealthTypes;
import com.intel.bkp.bkps.rest.health.model.ResourceType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class HealthServiceTest {

    @Mock
    private ApplicationContext context;

    @Mock
    private DatabaseCheckerService databaseChecker;

    @Mock
    private SecurityProviderCheckerService securityProviderChecker;

    @Mock
    private Environment environment;

    @InjectMocks
    @Spy
    private HealthService sut;

    @Test
    void check_DefaultTypeForHttp_ReturnsShallowResponse() {
        //given
        List<HealthServiceStatus> expectedItems = mockShallowResponse(null);

        //when
        HealthResponse actual = sut.check(HealthTypes.SHALLOW);

        //then
        validateResponse(expectedItems, actual, HealthTypes.SHALLOW.getName().toLowerCase(), false);
    }

    @Test
    void check_ShallowTypeForHttps_ReturnsShallowResponse() {
        //given
        List<HealthServiceStatus> expectedItems = mockShallowResponse("https");

        //when
        HealthResponse actual = sut.check(HealthTypes.SHALLOW);

        //then
        validateResponse(expectedItems, actual, HealthTypes.SHALLOW.getName().toLowerCase(), false);
    }

    @Test
    void check_SlaTypeForHttp_ReturnsShallowResponse() {
        //given
        List<HealthServiceStatus> expectedItems = mockShallowResponse(null);
        expectedItems.add(HealthServiceStatus.ok(ResourceType.DATABASE));
        expectedItems.add(HealthServiceStatus.ok(ResourceType.SECURITY_PROVIDER));
        when(databaseChecker.check()).thenReturn(HealthServiceStatus.ok(ResourceType.DATABASE));
        when(securityProviderChecker.check()).thenReturn(HealthServiceStatus.ok(ResourceType.SECURITY_PROVIDER));

        //when
        HealthResponse actual = sut.check(HealthTypes.SLA);

        //then
        validateResponse(expectedItems, actual, HealthTypes.SLA.getName().toLowerCase(), true);
    }

    @Test
    void check_StatusOverall_ReturnsOk() {
        //given
        when(databaseChecker.check()).thenReturn(HealthServiceStatus.ok(ResourceType.DATABASE));
        when(securityProviderChecker.check()).thenReturn(HealthServiceStatus.ok(ResourceType.SECURITY_PROVIDER));

        //when
        HttpStatus actual = sut.statusCheck(Optional.empty());

        //then
        assertEquals(HttpStatus.OK, actual);
    }

    @Test
    void check_StatusDatabase_ReturnsOk() {
        //given
        when(databaseChecker.check()).thenReturn(HealthServiceStatus.ok(ResourceType.DATABASE));

        //when
        HttpStatus actual = sut.statusCheck(Optional.of(ResourceType.DATABASE));

        //then
        assertEquals(HttpStatus.OK, actual);
    }

    @Test
    void check_StatusDatabase_Returns500() {
        //given
        when(databaseChecker.check()).thenReturn(HealthServiceStatus.error(ResourceType.DATABASE));

        //when
        HttpStatus actual = sut.statusCheck(Optional.of(ResourceType.DATABASE));

        //then
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, actual);
    }


    private List<HealthServiceStatus> mockShallowResponse(String httpsMockedVal) {
        when(context.getEnvironment()).thenReturn(environment);
        ReflectionTestUtils.setField(sut, "version", "1.9.1-TEST");
        ReflectionTestUtils.setField(sut, "name", "TestService");
        when(environment.getProperty("server.ssl.key-store")).thenReturn(httpsMockedVal);
        when(environment.getProperty("server.port")).thenReturn("7777");
        when(environment.getActiveProfiles()).thenReturn(new String[]{"dev"});
        return new ArrayList<>();
    }

    private void validateResponse(List<HealthServiceStatus> expectedItems, HealthResponse actual, String healthType, boolean detailed) {
        assertEquals("1.9.1-TEST", actual.getVersion());
        if (detailed) {
            assertEquals("dev", actual.getCurrentSetting());
        } else {
            assertNull(actual.getCurrentSetting());
        }

        assertEquals("TestService", actual.getName());
        assertEquals(expectedItems, actual.getItems());
    }

}
