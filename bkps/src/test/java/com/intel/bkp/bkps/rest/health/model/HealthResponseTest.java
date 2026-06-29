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

package com.intel.bkp.bkps.rest.health.model;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;


@ExtendWith(MockitoExtension.class)
public class HealthResponseTest {

    private final String version = "10.0.1-SNAPSHOT";
    private final String currentSetting = "prod";
    private final String serviceName = "Bkps Service";

    @Test
    void builder_ShouldBuildShallowResponse() {
        //given
        HealthResponse response = new HealthResponse();

        //when
        response
            .version(version)
            .currentSetting(currentSetting)
            .name(serviceName);

        //then
        assertEquals(version, response.getVersion());
        assertEquals(currentSetting, response.getCurrentSetting());
        assertEquals(serviceName, response.getName());

        assertEquals(new ArrayList<>(), response.getItems());
    }

    @Test
    void builder_ShouldBuildDetailedResponse() {
        //given
        HealthResponse response = new HealthResponse();
        List<HealthServiceStatus> list = new ArrayList<>();
        list.add(HealthServiceStatus.ok(ResourceType.DATABASE));

        //when
        response
            .version(version)
            .currentSetting(currentSetting)
            .name(serviceName)
            .items(list);

        //then
        assertEquals(version, response.getVersion());
        assertEquals(currentSetting, response.getCurrentSetting());
        assertEquals(serviceName, response.getName());
        assertEquals(list, response.getItems());
    }


}
