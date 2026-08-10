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

package com.intel.bkp.bkps.rest.validator;

import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
public class HexStringRequiredValidatorTest {

    @Mock
    private ConstraintValidatorContext context;

    @InjectMocks
    private HexStringRequiredValidator sut;

    @Test
    void isValid_WithNull_ReturnsTrue() {
        // when
        boolean result = sut.isValid(null, context);

        // then
        assertTrue(result);
    }

    @Test
    void isValid_WithEmpty_ReturnsTrue() {
        // when
        boolean result = sut.isValid("", context);

        // then
        assertTrue(result);
    }

    @Test
    void isValid_WithWhitespace_ReturnsFalse() {
        // when
        boolean result = sut.isValid(" ", context);

        // then
        assertFalse(result);
    }

    @Test
    void isValid_With1Char_ReturnsFalse() {
        // when
        boolean result = sut.isValid("A", context);

        // then
        assertFalse(result);
    }

    @Test
    void isValid_With1Zero_ReturnsFalse() {
        // when
        boolean result = sut.isValid("0", context);

        // then
        assertFalse(result);
    }

    @Test
    void isValid_With2Zeros_ReturnsTrue() {
        // when
        boolean result = sut.isValid("00", context);

        // then
        assertTrue(result);
    }

    @Test
    void isValid_WithSomeHexString_ReturnsTrue() {
        // when
        boolean result = sut.isValid("302211987777", context);

        // then
        assertTrue(result);
    }

}
