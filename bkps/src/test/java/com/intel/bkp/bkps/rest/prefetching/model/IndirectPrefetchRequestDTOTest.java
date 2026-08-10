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

package com.intel.bkp.bkps.rest.prefetching.model;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.function.Consumer;

import static com.intel.bkp.fpgacerts.model.Family.AGILEX;
import static com.intel.bkp.fpgacerts.model.Family.AGILEX_B;
import static com.intel.bkp.test.RandomUtils.generateDeviceIdHex;
import static com.intel.bkp.test.RandomUtils.generateRandomHex;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class IndirectPrefetchRequestDTOTest {

    private static final int PDI_LENGTH = 48;

    private static Validator validator;

    @RequiredArgsConstructor
    private enum TestCase {
        S10_VALID_DTO(0, dto -> {
            dto.setUid(generateDeviceIdHex());
        }),
        SKI_VALID_DTO(0, dto -> {
            dto.setUid(generateDeviceIdHex());
            dto.setFamilyId(AGILEX.getAsHex());
            dto.setDeviceIdEr("dummy");
        }),
        PDI_VALID_DTO(0, dto -> {
            dto.setUid(generateDeviceIdHex());
            dto.setFamilyId(AGILEX_B.getAsHex());
            dto.setPdi(generateRandomHex(PDI_LENGTH));
        }),
        UID_MISSING(1, dto -> {
        }),
        UID_NOT_IN_HEX_AND_TOO_SHORT(2, dto -> {
            dto.setUid("notHex");
        }),
        UID_NOT_IN_HEX(1, dto -> {
            dto.setUid("notHexBut16Chars");
        }),
        UID_TOO_SHORT(1, dto -> {
            dto.setUid("01020304050607");
        }),
        UID_TOO_LONG(1, dto -> {
            dto.setUid("010203040506070809");
        }),
        PDI_MISSING_WHEN_REQUIRED(1, dto -> {
            dto.setUid(generateDeviceIdHex());
            dto.setFamilyId(AGILEX_B.getAsHex());
        }),
        PDI_NOT_IN_HEX(1, dto -> {
            dto.setUid(generateDeviceIdHex());
            dto.setFamilyId(AGILEX_B.getAsHex());
            dto.setPdi("notHex");
        }),
        DEVICE_ID_ER_MISSING_WHEN_REQUIRED(1, dto -> {
            dto.setUid(generateDeviceIdHex());
            dto.setFamilyId(AGILEX.getAsHex());
        });

        @Getter
        private final int expectedViolationsCount;
        private final Consumer<IndirectPrefetchRequestDTO> fillDto;

        void fillDto(IndirectPrefetchRequestDTO dto) {
            fillDto.accept(dto);
        }
    }

    @BeforeAll
    static void setUpValidator() {
        try (ValidatorFactory validatorFactory = Validation.buildDefaultValidatorFactory()) {
            validator = validatorFactory.getValidator();
        }
    }

    @ParameterizedTest
    @EnumSource(TestCase.class)
    void validate_ReturnsExpectedNumberOfViolations(TestCase testCase) {
        // given
        final var dto = new IndirectPrefetchRequestDTO();
        testCase.fillDto(dto);

        // when
        final var result = validator.validate(dto);

        // then
        assertEquals(testCase.getExpectedViolationsCount(), result.size());
    }
}
