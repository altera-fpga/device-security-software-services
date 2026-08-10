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

package com.intel.bkp.bkps.rest.initialization.model.dto;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class EncryptedSealingKeyDTOTest {

    private Validator validator;

    @BeforeEach
    void setUp() {
        ValidatorFactory validatorFactory = Validation.buildDefaultValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @Test
    void validation_WithImportPubKey_Success() {
        //given
        EncryptedSealingKeyDTO sut = prepareEncryptedSealingKeyDTO();

        //when
        Set<ConstraintViolation<EncryptedSealingKeyDTO>> violations = validator.validate(sut);

        //then
        assertEquals(0, violations.size());
    }

    @Test
    void validation_WithoutImportPubKey_ReturnsViolation() {
        //given
        EncryptedSealingKeyDTO sut = prepareEncryptedSealingKeyDTOWithoutContent();

        //when
        Set<ConstraintViolation<EncryptedSealingKeyDTO>> violations = validator.validate(sut);

        //then
        assertEquals(1, violations.size());
    }

    @Test
    void validation_WithImportPubKeyTooBig_ReturnsViolation() {
        //given
        EncryptedSealingKeyDTO sut = prepareEncryptedSealingKeyDTOWithTooBigBody();

        //when
        Set<ConstraintViolation<EncryptedSealingKeyDTO>> violations = validator.validate(sut);

        //then
        assertEquals(1, violations.size());
    }

    @Test
    void validation_NotBase64_ReturnsViolation() {
        //given
        EncryptedSealingKeyDTO sut = prepareEncryptedSealingKeyDTONotBase64();

        //when
        Set<ConstraintViolation<EncryptedSealingKeyDTO>> violations = validator.validate(sut);

        //then
        assertEquals(1, violations.size());
    }

    private EncryptedSealingKeyDTO prepareEncryptedSealingKeyDTO() {
        return new EncryptedSealingKeyDTO(Base64.getEncoder().encodeToString("test".getBytes()));
    }

    private EncryptedSealingKeyDTO prepareEncryptedSealingKeyDTONotBase64() {
        return new EncryptedSealingKeyDTO("not_base_64");
    }

    private EncryptedSealingKeyDTO prepareEncryptedSealingKeyDTOWithoutContent() {
        return new EncryptedSealingKeyDTO();
    }

    // 1028 is the first value > 1024 which is Base64 compliant
    private EncryptedSealingKeyDTO prepareEncryptedSealingKeyDTOWithTooBigBody() {
        return new EncryptedSealingKeyDTO(new String(new char[1028]).replace('\0', 'A'));
    }

}
