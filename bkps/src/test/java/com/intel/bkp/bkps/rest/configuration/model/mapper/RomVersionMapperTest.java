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

import com.intel.bkp.bkps.domain.RomVersion;
import com.intel.bkp.bkps.rest.configuration.model.dto.RomVersionDTO;
import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class RomVersionMapperTest {

    private final RomVersionMapper sut = Mappers.getMapper(RomVersionMapper.class);

    @Test
    void toDto_WithNullInput_ReturnsNull() {
        // when
        RomVersionDTO actual = sut.toDto(null);

        // then
        assertNull(actual);
    }

    @Test
    void toDto_ReturnsDtoForGivenEntity() {
        // given
        RomVersion dto = new RomVersion();
        dto.setId(10L);
        dto.setValue(1000);

        // when
        RomVersionDTO actual = sut.toDto(dto);

        // then
        assertEquals(dto.getId(), actual.getId());
        assertEquals(dto.getValue(), actual.getValue());
    }

    @Test
    void toEntity_WithNullInput_ReturnsNull() {
        // when
        RomVersion actual = sut.toEntity(null);

        // then
        assertNull(actual);
    }

    @Test
    void toEntity_ReturnsEntityForGivenDto() {
        // given
        RomVersionDTO dto = new RomVersionDTO();
        dto.setId(10L);
        dto.setValue(1000);

        // when
        RomVersion actual = sut.toEntity(dto);

        // then
        assertEquals(dto.getId(), actual.getId());
        assertEquals(dto.getValue(), actual.getValue());
    }

    @Test
    void fromId_ReturnsObjectWithSetId() {
        // given
        RomVersion expected = new RomVersion();
        expected.setId(10L);

        // when
        RomVersion romVersion = sut.fromId(10L);

        // then
        assertEquals(expected, romVersion);
    }

    @Test
    void fromId_WithNullId_ReturnsNull() {
        // when
        RomVersion romVersion = sut.fromId(null);

        // then
        assertNull(romVersion);
    }
}
