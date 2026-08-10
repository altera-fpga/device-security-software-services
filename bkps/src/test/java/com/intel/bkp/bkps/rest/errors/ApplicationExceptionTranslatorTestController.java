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

package com.intel.bkp.bkps.rest.errors;

import com.intel.bkp.bkps.rest.configuration.model.dto.ServiceConfigurationDTO;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.core.exceptions.BKPNotFoundException;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.InputStream;

@RestController
public class ApplicationExceptionTranslatorTestController {

    @GetMapping("/test/constraint-violation-failure")
    public void constraintViolationFailure() {
        throw new ConstraintViolationException("", null);
    }

    @GetMapping("/test/bad-request-failure")
    public void badRequestFailure() {
        throw new BKPBadRequestException(ErrorCodeMap.UNKNOWN_ERROR);
    }

    @GetMapping("/test/internal-server-failure")
    public void internalServerFailure() {
        throw new BKPInternalServerException(ErrorCodeMap.UNKNOWN_ERROR);
    }

    @GetMapping("/test/not-found-failure")
    public void notFoundFailure() {
        throw new BKPNotFoundException(ErrorCodeMap.UNKNOWN_ERROR);
    }

    @PostMapping("/test/missing-iid-license")
    public void missingIIdLicense(@Valid @RequestBody ServiceConfigurationDTO serviceConfigurationDTO) {
    }

    @GetMapping("/test/message-not-readable")
    public void httpMessageNotReadableFailure() throws HttpMessageNotReadableException {
        throw new HttpMessageNotReadableException("id", new HttpInputMessage() {
            @Override
            public InputStream getBody() {
                return null;
            }

            @Override
            public HttpHeaders getHeaders() {
                return null;
            }
        });
    }

    @GetMapping("/test/missing-request-param")
    public void missingRequestParamFailure() throws MissingServletRequestParameterException {
        throw new MissingServletRequestParameterException("id", "integer");
    }
}
