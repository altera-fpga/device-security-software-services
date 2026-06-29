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

import com.intel.bkp.bkps.domain.BlackList;
import com.intel.bkp.bkps.domain.RomVersion;
import com.intel.bkp.bkps.domain.SdmBuildIdString;
import com.intel.bkp.bkps.domain.SdmSvn;
import com.intel.bkp.bkps.rest.configuration.model.dto.BlackListDTO;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = {BlackListMapperImpl.class, AttestationConfigurationMappingUtil.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class BlackListMapperTestIT {

    @Autowired
    private BlackListMapper sut;

    @Test
    void toDto_WithNullInput_ReturnsNull() {
        // when
        BlackListDTO actual = sut.toDto(null);

        // then
        assertNull(actual);
    }

    @Test
    void toDto_ReturnsDtoForGivenEntity_WithNullDetails() {
        // given
        BlackList dto = new BlackList();
        dto.setId(10L);
        dto.setRomVersions(null);
        dto.setSdmSvns(null);
        dto.setSdmBuildIdStrings(null);

        // when
        BlackListDTO actual = sut.toDto(dto);

        // then
        assertEquals(dto.getId(), actual.getId());

        assertNull(actual.getRomVersions());
        assertNull(actual.getSdmSvns());
        assertNull(actual.getSdmBuildIdStrings());

    }

    @Test
    void toDto_ReturnsDtoForGivenEntity() {
        // given
        BlackList dto = getBlackList();

        // when
        BlackListDTO actual = sut.toDto(dto);

        // then
        assertEquals(dto.getId(), actual.getId());

        List<Integer> romVersionsList = dto.getRomVersions().stream()
            .map(RomVersion::getValue).collect(Collectors.toList());
        assertEquals(romVersionsList, actual.getRomVersions());

        List<Integer> sdmSvnsList = dto.getSdmSvns().stream()
            .map(SdmSvn::getValue).collect(Collectors.toList());
        assertEquals(sdmSvnsList, actual.getSdmSvns());

        List<String> sdmBuildIdsList = dto.getSdmBuildIdStrings().stream()
            .map(SdmBuildIdString::getValue).collect(Collectors.toList());
        assertEquals(sdmBuildIdsList, actual.getSdmBuildIdStrings());

    }

    private static BlackList getBlackList() {
        BlackList dto = new BlackList();
        dto.setId(10L);
        RomVersion romVersion = new RomVersion(10L, 1000);
        Set<RomVersion> romVersions = new HashSet<>();
        romVersions.add(romVersion);
        dto.setRomVersions(romVersions);
        SdmSvn sdmSvn = new SdmSvn(20L, 2000);
        Set<SdmSvn> sdmSvns = new HashSet<>();
        sdmSvns.add(sdmSvn);
        dto.setSdmSvns(sdmSvns);
        SdmBuildIdString sdmBuildIdString = new SdmBuildIdString(30L, "10x");
        Set<SdmBuildIdString> sdmBuildIdStrings = new HashSet<>();
        sdmBuildIdStrings.add(sdmBuildIdString);
        dto.setSdmBuildIdStrings(sdmBuildIdStrings);
        return dto;
    }

    @Test
    void toEntity_WithNullInput_ReturnsNull() {
        // when
        BlackList actual = sut.toEntity(null);

        // then
        assertNull(actual);
    }

    @Test
    void toEntity_ReturnsEntityForGivenDto_WithNullDetails() {
        // given
        BlackListDTO dto = new BlackListDTO();
        dto.setId(10L);

        // when
        BlackList actual = sut.toEntity(dto);

        // then
        assertEquals(dto.getId(), actual.getId());

        assertNull(dto.getRomVersions());
        assertNull(dto.getSdmBuildIdStrings());
        assertNull(dto.getSdmSvns());

    }

    @Test
    void toEntity_ReturnsEntityForGivenDto() {
        // given
        BlackListDTO dto = new BlackListDTO();
        dto.setId(10L);
        dto.setRomVersions(Arrays.asList(10, 20, 30, 40));
        dto.setSdmBuildIdStrings(Arrays.asList("10x", "20x", "30x", "40x"));
        dto.setSdmSvns(Arrays.asList(1, 2, 3, 4));

        // when
        BlackList actual = sut.toEntity(dto);

        // then
        assertEquals(dto.getId(), actual.getId());

        List<Integer> romVersionsList = actual.getRomVersions().stream()
            .map(RomVersion::getValue).sorted().collect(Collectors.toList());

        assertEquals(dto.getRomVersions(), romVersionsList);

        List<String> sdmBuildIdsList = actual.getSdmBuildIdStrings().stream()
            .map(SdmBuildIdString::getValue).sorted().collect(Collectors.toList());
        assertEquals(dto.getSdmBuildIdStrings(), sdmBuildIdsList);

        List<Integer> sdmSvnsList = actual.getSdmSvns().stream()
            .map(SdmSvn::getValue).collect(Collectors.toList());
        assertEquals(dto.getSdmSvns(), sdmSvnsList);
    }

}
