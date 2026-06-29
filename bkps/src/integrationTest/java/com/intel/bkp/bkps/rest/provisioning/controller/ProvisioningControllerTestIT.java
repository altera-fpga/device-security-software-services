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

package com.intel.bkp.bkps.rest.provisioning.controller;

import com.intel.bkp.bkps.BkpsApp;
import com.intel.bkp.bkps.programmer.model.CommunicationStatus;
import com.intel.bkp.bkps.programmer.model.dto.MessageDTO;
import com.intel.bkp.bkps.programmer.model.dto.ResponseDTO;
import com.intel.bkp.bkps.rest.errors.ApplicationExceptionHandler;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ContextDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.service.ProvisioningService;
import com.intel.bkp.core.security.ISecurityProvider;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.web.PageableHandlerMethodArgumentResolver;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.ArrayList;
import java.util.List;

import static com.intel.bkp.bkps.rest.RestUtil.APPLICATION_JSON_UTF8;
import static com.intel.bkp.bkps.rest.RestUtil.convertObjectToJsonBytes;
import static com.intel.bkp.bkps.rest.RestUtil.createFormattingConversionService;
import static com.intel.bkp.bkps.rest.provisioning.ProvisioningResource.GET_NEXT;
import static com.intel.bkp.bkps.rest.provisioning.ProvisioningResource.PROVISIONING_NODE;
import static com.intel.bkp.core.utils.ApplicationConstants.REQUEST_BODY_STRING_MAX_SIZE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = BkpsApp.class)
@ActiveProfiles({"staticbouncycastle"})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class ProvisioningControllerTestIT {

    @MockBean
    private ProvisioningService provisioningService;

    @Autowired
    private MappingJackson2HttpMessageConverter jacksonMessageConverter;

    @Autowired
    private PageableHandlerMethodArgumentResolver pageableArgumentResolver;

    @Autowired
    private ApplicationExceptionHandler exceptionTranslator;

    @MockBean
    ISecurityProvider securityProvider;

    private MockMvc restMockMvc;

    private static final ContextDTO contextDTO = ContextDTO.from(new byte[5]);
    private static final ContextDTO emptyContextDTO = ContextDTO.empty();
    private static final ContextDTO invalidContextDTO = new ContextDTO("AA");
    private static final ContextDTO invalidTooLongContextDTO =
        new ContextDTO(StringUtils.repeat("A", REQUEST_BODY_STRING_MAX_SIZE + 2));

    private static final Long CFG_ID = 0L;
    private static final int API_VERSION = 1;
    private static final Integer SUPPORTED_COMMANDS = 1;
    private static final ResponseDTO JTAG_RESPONSE = ResponseDTO.from(new byte[]{0x01, 0x02});
    private static final List<ResponseDTO> JTAG_RESPONSES = List.of(JTAG_RESPONSE);
    private static final List<MessageDTO> JTAG_COMMANDS = new ArrayList<>();

    private static final ProvisioningRequestDTO PROV_REQUEST_DTO =
        new ProvisioningRequestDTO(contextDTO, CFG_ID, API_VERSION, SUPPORTED_COMMANDS, JTAG_RESPONSES);

    private static final ProvisioningRequestDTO PROV_REQUEST_DTO_EMPTY_CONTEXT =
        new ProvisioningRequestDTO(emptyContextDTO, CFG_ID, API_VERSION, SUPPORTED_COMMANDS, JTAG_RESPONSES);

    private static final ProvisioningRequestDTO PROV_REQUEST_DTO_INVALID_CONTEXT =
        new ProvisioningRequestDTO(invalidContextDTO, CFG_ID, API_VERSION, SUPPORTED_COMMANDS, JTAG_RESPONSES);

    private static final ProvisioningRequestDTO PROV_REQUEST_DTO_TOO_LONG_CONTEXT =
        new ProvisioningRequestDTO(invalidTooLongContextDTO, CFG_ID, API_VERSION, SUPPORTED_COMMANDS, JTAG_RESPONSES);

    private static final String PROV_REQUEST_DTO_NO_CONTEXT =
        "{\"cfgId\":0,\"apiVersion\":1,\"supportedCommands\":1,\"jtagResponses\":[]}";

    private static final String PROV_REQUEST_DTO_NULL_CONTEXT =
        "{\"context\":{},\"cfgId\":0,\"apiVersion\":1,\"supportedCommands\":1,\"jtagResponses\":[]}";

    private static final ProvisioningResponseDTO PROV_RESPONSE_DTO =
        new ProvisioningResponseDTO(contextDTO, CommunicationStatus.CONTINUE.getStatus(), API_VERSION, JTAG_COMMANDS);

    @BeforeEach
    void setup() {
        final ProvisioningController provisioningController = new ProvisioningController(provisioningService);
        this.restMockMvc = MockMvcBuilders.standaloneSetup(provisioningController)
            .setCustomArgumentResolvers(pageableArgumentResolver)
            .setControllerAdvice(exceptionTranslator)
            .setConversionService(createFormattingConversionService())
            .setMessageConverters(jacksonMessageConverter).build();
    }

    @Test
    void getNext_ReturnSuccess() throws Exception {
        // given
        mockGetNextResponse();

        // when
        performProvisioningWithContentAndExpectOk(PROV_REQUEST_DTO);

        // then
        verifyProvGetNext(PROV_REQUEST_DTO);
    }

    @Test
    void getNext_WithEmptyContext_ReturnSuccess() throws Exception {
        // given
        mockGetNextResponse();

        // when
        performProvisioningWithContentAndExpectOk(PROV_REQUEST_DTO_EMPTY_CONTEXT);

        // then
        verifyProvGetNext(PROV_REQUEST_DTO_EMPTY_CONTEXT);
    }

    @Test
    void getNext_WithoutContext_ReturnsBadRequest() throws Exception {
        // when
        performProvisioningWithContentAndExpectBadRequest(PROV_REQUEST_DTO_NO_CONTEXT);

        // then
        verifyNothingHappened();
    }

    @Test
    void getNext_WithNullContextValue_ReturnsBadRequest() throws Exception {
        // when
        performProvisioningWithContentAndExpectBadRequest(PROV_REQUEST_DTO_NULL_CONTEXT);

        // then
        verifyNothingHappened();
    }

    @Test
    void getNext_WithInvalidRequestDto_ReturnsBadRequest() throws Exception {
        // when
        performProvisioningWithContentAndExpectBadRequest(PROV_REQUEST_DTO_INVALID_CONTEXT);

        // then
        verifyNothingHappened();
    }

    @Test
    void getNext_WithInvalidTooLongRequestDto_ReturnsBadRequest() throws Exception {
        // when
        performProvisioningWithContentAndExpectBadRequest(PROV_REQUEST_DTO_TOO_LONG_CONTEXT);

        // then
        verifyNothingHappened();
    }

    private void mockGetNextResponse() {
        when(provisioningService.getNext(any())).thenReturn(PROV_RESPONSE_DTO);
    }

    private void performProvisioningWithContentAndExpectBadRequest(ProvisioningRequestDTO request) throws Exception {
        performProvisioningWithContentAndExpectBadRequest(new String(convertObjectToJsonBytes(request)));
    }

    private void performProvisioningWithContentAndExpectBadRequest(String request) throws Exception {
        performWithContentAndExpectBadRequest(GET_NEXT, request);
    }

    private void performWithContentAndExpectBadRequest(String resource, String request) throws Exception {
        restMockMvc.perform(post(PROVISIONING_NODE + resource)
                .contentType(APPLICATION_JSON_UTF8)
                .content(request))
            .andExpect(status().isBadRequest())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
            .andExpect(jsonPath("$.status.code").value(ErrorCodeMap.INVALID_FIELDS_IN_PAYLOAD.getCode()))
            .andExpect(jsonPath("$.status.message").value(ErrorCodeMap.INVALID_FIELDS_IN_PAYLOAD.getExternalMessage()));
    }

    private void performProvisioningWithContentAndExpectOk(ProvisioningRequestDTO request) throws Exception {
        performWithContentAndExpectOk(GET_NEXT, request, PROV_RESPONSE_DTO);
    }

    private void performWithContentAndExpectOk(String resource, Object request, Object response) throws Exception {
        restMockMvc.perform(post(PROVISIONING_NODE + resource)
                .contentType(APPLICATION_JSON_UTF8)
                .content(convertObjectToJsonBytes(request)))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
            .andExpect(content().bytes(convertObjectToJsonBytes(response)));
    }

    private void verifyNothingHappened() {
        verifyNoInteractions(provisioningService);
    }

    private void verifyProvGetNext(ProvisioningRequestDTO expectedDTO) {
        final var requestDTOCaptor = ArgumentCaptor.forClass(ProvisioningRequestDTO.class);
        verify(provisioningService).getNext(requestDTOCaptor.capture());

        final var actualDTO = requestDTOCaptor.getValue();
        assertEquals(expectedDTO.getContext().getValue(), actualDTO.getContext().getValue());
        assertEquals(expectedDTO.getApiVersion(), actualDTO.getApiVersion());
        assertEquals(expectedDTO.getCfgId(), actualDTO.getCfgId());
        assertEquals(expectedDTO.getSupportedCommands(), actualDTO.getSupportedCommands());
        assertEquals(expectedDTO.getJtagResponses().size(), actualDTO.getJtagResponses().size());
    }
}
