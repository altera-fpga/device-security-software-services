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
import org.springframework.web.multipart.MultipartFile;

import static com.intel.bkp.core.utils.ApplicationConstants.REQUEST_BODY_STRING_MAX_SIZE;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FilesRequiredValidatorTest {

    @Mock
    private ConstraintValidatorContext context;

    @Mock
    private MultipartFile file1;

    @Mock
    private MultipartFile file2;

    @InjectMocks
    private FilesRequiredValidator sut;

    @Test
    void isValid_WithNull_ReturnsFalse() {
        // when
        boolean result = sut.isValid(null, context);

        // then
        assertFalse(result);
    }

    @Test
    void isValid_WithNullFile_ReturnsFalse() {
        // given
        final MultipartFile[] data = {null, file2};

        // when
        boolean result = sut.isValid(data, context);

        // then
        assertFalse(result);
    }

    @Test
    void isValid_WithEmptyFile_ReturnsFalse() {
        // given
        when(file1.isEmpty()).thenReturn(true);

        // when
        boolean result = sut.isValid(getValidatorData(), context);

        // then
        assertFalse(result);
    }

    @Test
    void isValid_WithValidMaxSize_ReturnsTrue() {
        // given
        long validFileSize = REQUEST_BODY_STRING_MAX_SIZE / 3;
        when(file1.getSize()).thenReturn(validFileSize);
        when(file2.getSize()).thenReturn(validFileSize);

        // when
        boolean result = sut.isValid(getValidatorData(), context);

        // then
        assertTrue(result);
    }

    @Test
    void isValid_WithInvalidMaxSize_ReturnsFalse() {
        // given
        long validFileSize = REQUEST_BODY_STRING_MAX_SIZE / 2;
        when(file1.getSize()).thenReturn(validFileSize + 10);
        when(file2.getSize()).thenReturn(validFileSize);

        // when
        boolean result = sut.isValid(getValidatorData(), context);

        // then
        assertFalse(result);
    }

    private MultipartFile[] getValidatorData() {
        return new MultipartFile[]{file1, file2};
    }
}
