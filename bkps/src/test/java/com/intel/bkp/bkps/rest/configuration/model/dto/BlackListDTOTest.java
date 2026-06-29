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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static com.intel.bkp.core.utils.ApplicationConstants.REQUEST_BODY_MAX_LIST_SIZE;
import static com.intel.bkp.core.utils.ApplicationConstants.REQUEST_BODY_STRING_MAX_SIZE;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class BlackListDTOTest {

    private static final String VALID_STRING = "test";
    private static final String INVALID_STRING = StringUtils.repeat("*", REQUEST_BODY_STRING_MAX_SIZE + 1);
    private static final List<Integer> VALID_INTEGER_LIST = new ArrayList<>();
    private static final List<String> VALID_STRING_LIST = new ArrayList<>();
    private static final List<Integer> INVALID_INTEGER_LIST = Collections.nCopies(REQUEST_BODY_MAX_LIST_SIZE + 1, 0);
    private static final List<String> INVALID_STRING_LIST =
        Collections.nCopies(REQUEST_BODY_MAX_LIST_SIZE + 1, VALID_STRING);
    private static final List<String> INVALID_STRING_LIST_CONTENT = Collections.singletonList(INVALID_STRING);

    private Validator validator;

    @BeforeEach
    void setUp() {
        ValidatorFactory validatorFactory = Validation.buildDefaultValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @Test
    void validation_WithAllValid_Success() {
        //given
        BlackListDTO sut = new BlackListDTO(1L, VALID_INTEGER_LIST, VALID_STRING_LIST, VALID_INTEGER_LIST);

        //when
        Set<ConstraintViolation<BlackListDTO>> violations = validator.validate(sut);

        //then
        assertEquals(0, violations.size());
    }

    @Test
    void validation_WithInvalidRomVersionsList_ReportsViolation() {
        //given
        BlackListDTO sut = new BlackListDTO(1L, INVALID_INTEGER_LIST, VALID_STRING_LIST, VALID_INTEGER_LIST);

        //when
        Set<ConstraintViolation<BlackListDTO>> violations = validator.validate(sut);

        //then
        assertEquals(1, violations.size());
    }

    @Test
    void validation_WithInvalidSdmSvnsList_ReportsViolation() {
        //given
        BlackListDTO sut = new BlackListDTO(1L, VALID_INTEGER_LIST, VALID_STRING_LIST, INVALID_INTEGER_LIST);

        //when
        Set<ConstraintViolation<BlackListDTO>> violations = validator.validate(sut);

        //then
        assertEquals(1, violations.size());
    }

    @Test
    void validation_WithInvalidSdmBuildIdStringsList_ReportsViolation() {
        //given
        BlackListDTO sut = new BlackListDTO(1L, VALID_INTEGER_LIST, INVALID_STRING_LIST, VALID_INTEGER_LIST);

        //when
        Set<ConstraintViolation<BlackListDTO>> violations = validator.validate(sut);

        //then
        assertEquals(1, violations.size());
    }

    @Test
    void validation_WithInvalidSdmBuildIdStringsListContent_ReportsViolation() {
        //given
        BlackListDTO sut = new BlackListDTO(1L, VALID_INTEGER_LIST, INVALID_STRING_LIST_CONTENT, VALID_INTEGER_LIST);

        //when
        Set<ConstraintViolation<BlackListDTO>> violations = validator.validate(sut);

        //then
        assertEquals(1, violations.size());
    }

    @Test
    void validation_WithAllInvalid_ReportsMultipleViolations() {
        //given
        BlackListDTO sut = new BlackListDTO(1L, INVALID_INTEGER_LIST, INVALID_STRING_LIST, INVALID_INTEGER_LIST);

        //when
        Set<ConstraintViolation<BlackListDTO>> violations = validator.validate(sut);

        //then
        assertEquals(3, violations.size());
    }

}
