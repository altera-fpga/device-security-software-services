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

import com.intel.bkp.bkps.BkpsApp;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.core.security.ISecurityProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test class for the ExceptionTranslator controller advice.
 *
 * @see ApplicationExceptionHandler
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = BkpsApp.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class ApplicationExceptionImpHandlerTestIT {

    @Autowired
    private ApplicationExceptionTranslatorTestController controller;

    @Autowired
    private ApplicationExceptionHandler applicationExceptionHandler;

    @Autowired
    private MappingJackson2HttpMessageConverter jacksonMessageConverter;

    @MockBean
    private ISecurityProvider securityService;

    private MockMvc mockMvc;

    @BeforeEach
    void setup() {
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
            .setControllerAdvice(applicationExceptionHandler)
            .setMessageConverters(jacksonMessageConverter)
            .build();
    }

    @Test
    void handleConstraintViolationExceptions_ReturnsProperStatusAndBody() throws Exception {
        mockMvc.perform(get("/test/constraint-violation-failure"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.status.code").value(ErrorCodeMap.INVALID_FIELDS_IN_PAYLOAD.getCode()))
            .andExpect(jsonPath("$.status.message").value(ErrorCodeMap.INVALID_FIELDS_IN_PAYLOAD
                .getExternalMessage()));
    }

    @Test
    void handleBadRequestExceptions_ReturnsProperStatusAndBody() throws Exception {
        mockMvc.perform(get("/test/bad-request-failure"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.status.code").value(ErrorCodeMap.UNKNOWN_ERROR.getCode()))
            .andExpect(jsonPath("$.status.message").value(ErrorCodeMap.UNKNOWN_ERROR
                .getExternalMessage()));
    }

    @Test
    void handleInternalServerExceptions_ReturnsProperStatusAndBody() throws Exception {
        mockMvc.perform(get("/test/internal-server-failure"))
            .andExpect(status().isInternalServerError())
            .andExpect(jsonPath("$.status.code").value(ErrorCodeMap.UNKNOWN_ERROR.getCode()))
            .andExpect(jsonPath("$.status.message").value(ErrorCodeMap.UNKNOWN_ERROR.getExternalMessage()));
    }

    @Test
    void handleNotFoundExceptions_ReturnsProperStatusAndBody() throws Exception {
        mockMvc.perform(get("/test/not-found-failure"))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.status.code").value(ErrorCodeMap.UNKNOWN_ERROR.getCode()))
            .andExpect(jsonPath("$.status.message").value(ErrorCodeMap.UNKNOWN_ERROR
                .getExternalMessage()));
    }

    @Test
    void handleHttpMessageNotReadable_ReturnsBadRequest() throws Exception {
        mockMvc.perform(get("/test/message-not-readable"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.status.code").value(ErrorCodeMap.INVALID_FIELDS_IN_PAYLOAD.getCode()))
            .andExpect(jsonPath("$.status.message").value(ErrorCodeMap.INVALID_FIELDS_IN_PAYLOAD
                .getExternalMessage()));
    }

    @Test
    void handleMissingServletRequestParameter_ReturnsBadRequest() throws Exception {
        mockMvc.perform(get("/test/missing-request-param"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.status.code").value(ErrorCodeMap.INVALID_FIELDS_IN_PAYLOAD.getCode()))
            .andExpect(jsonPath("$.status.message").value(ErrorCodeMap.INVALID_FIELDS_IN_PAYLOAD
                .getExternalMessage()));
    }
}
