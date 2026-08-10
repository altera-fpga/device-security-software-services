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

package com.intel.bkp.bkps.rest.configuration.model.dto;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class EfusesPublicDTOTest {

    private static final int VALID_SIZE_1 = 256;
    private static final int VALID_SIZE_2 = 1024;
    private static final int INVALID_SIZE = VALID_SIZE_1 + 1;
    private static final String VALID_STRING_1 = StringUtils.repeat("00", VALID_SIZE_1);
    private static final String VALID_STRING_2 = StringUtils.repeat("00", VALID_SIZE_2);
    private static final String INVALID_STRING = StringUtils.repeat("00", INVALID_SIZE);
    private static final String NOT_HEX_STRING = StringUtils.repeat("*", VALID_SIZE_1);

    private Validator validator;

    @BeforeEach
    void setUp() {
        ValidatorFactory validatorFactory = Validation.buildDefaultValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @Test
    void validation_WithAllValid1_Success() {
        //given
        EfusesPublicDTO sut = new EfusesPublicDTO(VALID_STRING_1, VALID_STRING_1);

        //when
        Set<ConstraintViolation<EfusesPublicDTO>> violations = validator.validate(sut);

        //then
        assertEquals(0, violations.size());
    }

    @Test
    void validation_WithAllValid2_Success() {
        //given
        EfusesPublicDTO sut = new EfusesPublicDTO(VALID_STRING_2, VALID_STRING_2);

        //when
        Set<ConstraintViolation<EfusesPublicDTO>> violations = validator.validate(sut);

        //then
        assertEquals(0, violations.size());
    }

    @Test
    void validation_WithInvalidMask1_Success() {
        //given
        EfusesPublicDTO sut = new EfusesPublicDTO(INVALID_STRING, VALID_STRING_1);

        //when
        Set<ConstraintViolation<EfusesPublicDTO>> violations = validator.validate(sut);

        //then
        assertEquals(1, violations.size());
    }

    @Test
    void validation_WithInvalidMask2_Success() {
        //given
        EfusesPublicDTO sut = new EfusesPublicDTO(INVALID_STRING, VALID_STRING_2);

        //when
        Set<ConstraintViolation<EfusesPublicDTO>> violations = validator.validate(sut);

        //then
        assertEquals(1, violations.size());
    }

    @Test
    void validation_WithNotHexMask_Success() {
        //given
        EfusesPublicDTO sut = new EfusesPublicDTO(NOT_HEX_STRING, VALID_STRING_1);

        //when
        Set<ConstraintViolation<EfusesPublicDTO>> violations = validator.validate(sut);

        //then
        assertEquals(1, violations.size());
    }

    @Test
    void validation_WithInvalidValue1_Success() {
        //given
        EfusesPublicDTO sut = new EfusesPublicDTO(VALID_STRING_1, INVALID_STRING);

        //when
        Set<ConstraintViolation<EfusesPublicDTO>> violations = validator.validate(sut);

        //then
        assertEquals(1, violations.size());
    }

    @Test
    void validation_WithInvalidValue2_Success() {
        //given
        EfusesPublicDTO sut = new EfusesPublicDTO(VALID_STRING_2, INVALID_STRING);

        //when
        Set<ConstraintViolation<EfusesPublicDTO>> violations = validator.validate(sut);

        //then
        assertEquals(1, violations.size());
    }

    @Test
    void validation_WithNotHexValue_Success() {
        //given
        EfusesPublicDTO sut = new EfusesPublicDTO(VALID_STRING_1, NOT_HEX_STRING);

        //when
        Set<ConstraintViolation<EfusesPublicDTO>> violations = validator.validate(sut);

        //then
        assertEquals(1, violations.size());
    }

    @Test
    void validation_WithAllInvalid_Success() {
        //given
        EfusesPublicDTO sut = new EfusesPublicDTO(INVALID_STRING, INVALID_STRING);

        //when
        Set<ConstraintViolation<EfusesPublicDTO>> violations = validator.validate(sut);

        //then
        assertEquals(2, violations.size());
    }

    @Test
    void validation_WithAllNotHex_Success() {
        //given
        EfusesPublicDTO sut = new EfusesPublicDTO(NOT_HEX_STRING, NOT_HEX_STRING);

        //when
        Set<ConstraintViolation<EfusesPublicDTO>> violations = validator.validate(sut);

        //then
        assertEquals(2, violations.size());
    }

}
