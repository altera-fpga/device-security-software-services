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

package com.intel.bkp.bkps.rest.health.checker;

import com.intel.bkp.bkps.rest.health.model.HealthServiceStatus;
import com.intel.bkp.bkps.rest.health.model.HealthStatus;
import com.intel.bkp.bkps.rest.health.model.ResourceType;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
public class DatabaseCheckerServiceTest {

    private final ResourceType serviceName = ResourceType.DATABASE;

    @Mock
    private EntityManager entityManager;

    @InjectMocks
    private DatabaseCheckerService sut;

    @Test
    void check_ShouldReturnOKStatus() {
        // given
        Query query = mock(Query.class);
        Mockito.when(entityManager.createNativeQuery(anyString())).thenReturn(query);

        // when
        HealthServiceStatus actual = sut.check();

        // then
        HealthServiceStatus expected = new HealthServiceStatus(serviceName, HealthStatus.OK);
        assertEquals(actual, expected);
    }

    @Test
    void check_ShouldReturn_ErrorStatus() {
        // given
        Mockito.when(entityManager.createNativeQuery(anyString()))
            .thenThrow(new RuntimeException("Connection refused"));

        // when
        HealthServiceStatus actual = sut.check();

        // then
        HealthServiceStatus expected = new HealthServiceStatus(serviceName, HealthStatus.ERROR);
        assertEquals(actual, expected);
    }
}
