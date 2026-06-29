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

package com.intel.bkp.bkps.rest.configuration.model.mapper;

import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.rest.configuration.model.dto.ServiceConfigurationDTO;
import com.intel.bkp.bkps.rest.configuration.model.dto.ServiceConfigurationResponseDTO;
import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class ServiceConfigurationMapperTest {

    private final ServiceConfigurationMapper sut = Mappers.getMapper(ServiceConfigurationMapper.class);

    @Test
    void toResultDto_WithNulDTOlInput_ReturnsNull() {
        // given
        ServiceConfigurationDTO serviceConfigurationDTO = null;

        // when
        ServiceConfigurationResponseDTO actual = sut.toResultDto(serviceConfigurationDTO);

        // then
        assertNull(actual);
    }

    @Test
    void toResultDto_WithNullEntityInput_ReturnsNull() {
        // given
        ServiceConfiguration entity = null;

        // when
        ServiceConfigurationResponseDTO actual = sut.toResultDto(entity);

        // then
        assertNull(actual);
    }

    @Test
    void toResultDto_WithEntity_ReturnsDTO() {
        // given
        ServiceConfiguration entity = new ServiceConfiguration();
        entity.setId(100L);
        entity.setName("test");

        // when
        ServiceConfigurationResponseDTO actual = sut.toResultDto(entity);

        // then
        assertEquals(entity.getId(), actual.getId());
        assertEquals(entity.getName(), actual.getName());
    }
}
