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

package com.intel.bkp.bkps.rest.initialization.model.mapper;

import com.intel.bkp.bkps.domain.SigningKeyEntity;
import com.intel.bkp.bkps.domain.enumeration.SigningKeyStatus;
import com.intel.bkp.bkps.rest.initialization.model.dto.SigningKeyDTO;
import com.intel.bkp.bkps.rest.initialization.model.dto.SigningKeyResponseDTO;
import com.intel.bkp.bkps.utils.DateMapper;
import com.intel.bkp.bkps.utils.DateMapperImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = {SigningKeyMapperImpl.class, SigningKeyChainMapperImpl.class, DateMapperImpl.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class SigningKeyMapperTestIT {

    @Autowired
    private DateMapper dateMapper;

    @Autowired
    private SigningKeyMapper sut;

    @Test
    void toDto_WithNullInput_ReturnsNull() {

        // when
        final SigningKeyDTO dto = sut.toDto(null);

        // then
        assertNull(dto);
    }

    @Test
    void toDto_WithInput_ReturnsDto() {
        // given
        SigningKeyEntity entity = new SigningKeyEntity();
        final long id = 2L;
        entity.setId(id);

        // when
        final SigningKeyDTO dto = sut.toDto(entity);

        // then
        assertEquals((Long) id, dto.getSigningKeyId());
    }

    @Test
    void toResultDto_WithNullInput_ReturnsNull() {

        // when
        final SigningKeyResponseDTO signingKeyResponseDTO = sut.toResultDto(null);

        // then
        assertNull(signingKeyResponseDTO);
    }

    @Test
    void toResultDto_Success() {
        // given
        SigningKeyEntity entity = new SigningKeyEntity();
        final long id = 2L;
        entity.setId(id);
        entity.setCreatedAt(Instant.now());
        entity.setStatus(SigningKeyStatus.ENABLED);

        // when
        final SigningKeyResponseDTO signingKeyResponseDTO = sut.toResultDto(entity);

        // then
        assertEquals(entity.getStatus(), signingKeyResponseDTO.getStatus());
        assertEquals(entity.getId(), signingKeyResponseDTO.getSigningKeyId());
        assertEquals(dateMapper.asString(entity.getCreatedAt()), signingKeyResponseDTO.getCreated());
    }
}
