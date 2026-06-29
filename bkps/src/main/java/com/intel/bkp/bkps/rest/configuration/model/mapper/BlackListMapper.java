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
import com.intel.bkp.bkps.rest.configuration.model.mapper.AttestationConfigurationMappingUtil.RomVersionAnn;
import com.intel.bkp.bkps.rest.configuration.model.mapper.AttestationConfigurationMappingUtil.SdmBuildIdStringAnn;
import com.intel.bkp.bkps.rest.configuration.model.mapper.AttestationConfigurationMappingUtil.SdmSvnAnn;
import com.intel.bkp.bkps.utils.EntityMapper;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import java.util.Optional;

/**
 * Mapper for the entity BlackList and its DTO BlackListDTO.
 */
@Mapper(componentModel = "spring", uses = AttestationConfigurationMappingUtil.class)
public interface BlackListMapper extends EntityMapper<BlackListDTO, BlackList> {

    @Mapping(source = "romVersions", target = "romVersions", qualifiedBy = RomVersionAnn.class)
    @Mapping(source = "sdmBuildIdStrings", target = "sdmBuildIdStrings", qualifiedBy = SdmBuildIdStringAnn.class)
    @Mapping(source = "sdmSvns", target = "sdmSvns", qualifiedBy = SdmSvnAnn.class)
    BlackListDTO toDto(BlackList blackList);

    @Mapping(source = "romVersions", target = "romVersions", qualifiedBy = RomVersionAnn.class)
    @Mapping(source = "sdmBuildIdStrings", target = "sdmBuildIdStrings", qualifiedBy = SdmBuildIdStringAnn.class)
    @Mapping(source = "sdmSvns", target = "sdmSvns", qualifiedBy = SdmSvnAnn.class)
    BlackList toEntity(BlackListDTO blackListDTO);

    @RomVersionAnn
    default Integer romVersion(RomVersion obj) {
        return obj.getValue();
    }

    @RomVersionAnn
    default RomVersion romVersionFromValue(Integer value) {
        return Optional.ofNullable(value).map(RomVersion::new).orElse(null);
    }

    @SdmBuildIdStringAnn
    default String sdmBuildIdString(SdmBuildIdString obj) {
        return obj.getValue();
    }

    @SdmBuildIdStringAnn
    default SdmBuildIdString sdmBuildIdStringFromValue(String value) {
        return Optional.ofNullable(value).map(SdmBuildIdString::new).orElse(null);
    }

    @SdmSvnAnn
    default Integer sdmSvn(SdmSvn obj) {
        return obj.getValue();
    }

    @SdmSvnAnn
    default SdmSvn sdmSvnFromValue(Integer value) {
        return Optional.ofNullable(value).map(SdmSvn::new).orElse(null);
    }
}
