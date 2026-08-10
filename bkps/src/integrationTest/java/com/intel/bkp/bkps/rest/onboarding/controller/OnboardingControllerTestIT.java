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

package com.intel.bkp.bkps.rest.onboarding.controller;

import com.intel.bkp.bkps.BkpsApp;
import com.intel.bkp.bkps.programmer.model.dto.MessageDTO;
import com.intel.bkp.bkps.programmer.model.dto.ResponseDTO;
import com.intel.bkp.bkps.rest.errors.ApplicationExceptionHandler;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.onboarding.model.DirectPrefetchRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.DirectPrefetchResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.PufActivateRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.PufActivateResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.service.OnboardingService;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ContextDTO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
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

import static com.intel.bkp.bkps.programmer.model.CommunicationStatus.CONTINUE;
import static com.intel.bkp.bkps.rest.RestUtil.APPLICATION_JSON_UTF8;
import static com.intel.bkp.bkps.rest.RestUtil.convertObjectToJsonBytes;
import static com.intel.bkp.bkps.rest.RestUtil.createFormattingConversionService;
import static com.intel.bkp.bkps.rest.onboarding.OnboardingResource.PREFETCH_NEXT;
import static com.intel.bkp.bkps.rest.onboarding.OnboardingResource.PUF_ACTIVATE;
import static java.util.Collections.nCopies;
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
public class OnboardingControllerTestIT {

    private static final ContextDTO CONTEXT_DTO = ContextDTO.from(new byte[5]);
    private static final int API_VERSION = 1;
    private static final int PUF_TYPE = 1;
    private static final Integer SUPPORTED_COMMANDS = 1;
    private static final ResponseDTO JTAG_RESPONSE = ResponseDTO.from(new byte[]{0x01, 0x02});
    private static final List<MessageDTO> JTAG_COMMANDS = new ArrayList<>();

    private static final DirectPrefetchRequestDTO PREFETCH_REQUEST_DTO =
        new DirectPrefetchRequestDTO(API_VERSION, SUPPORTED_COMMANDS, nCopies(1, JTAG_RESPONSE));

    private static final DirectPrefetchRequestDTO PREFETCH_REQUEST_DTO_MAX_NUMBER_OF_RESPONSES =
        new DirectPrefetchRequestDTO(API_VERSION, SUPPORTED_COMMANDS, nCopies(4, JTAG_RESPONSE));

    private static final DirectPrefetchRequestDTO PREFETCH_REQUEST_DTO_TOO_MANY_RESPONSES =
        new DirectPrefetchRequestDTO(API_VERSION, SUPPORTED_COMMANDS, nCopies(5, JTAG_RESPONSE));

    private static final String PREFETCH_REQUEST_DTO_NO_API_VERSION =
        "{\"supportedCommands\":1,\"jtagResponses\":[]}";

    private static final DirectPrefetchResponseDTO PREFETCH_RESPONSE_DTO =
        new DirectPrefetchResponseDTO(CONTINUE.getStatus(), API_VERSION, JTAG_COMMANDS);

    private static final PufActivateRequestDTO PUF_ACTIVATE_REQUEST_DTO =
        new PufActivateRequestDTO(CONTEXT_DTO, PUF_TYPE, API_VERSION, SUPPORTED_COMMANDS, nCopies(1, JTAG_RESPONSE));
    private static final PufActivateResponseDTO PUF_ACTIVATE_RESPONSE_DTO =
        new PufActivateResponseDTO(CONTEXT_DTO, CONTINUE.getStatus(), API_VERSION, JTAG_COMMANDS);

    private MockMvc restMockMvc;

    @MockitoBean
    private OnboardingService onboardingService;

    @Autowired
    private MappingJackson2HttpMessageConverter jacksonMessageConverter;

    @Autowired
    private PageableHandlerMethodArgumentResolver pageableArgumentResolver;

    @Autowired
    private ApplicationExceptionHandler exceptionTranslator;

    @BeforeEach
    void setup() {
        final OnboardingController onboardingController = new OnboardingController(onboardingService);
        this.restMockMvc = MockMvcBuilders.standaloneSetup(onboardingController)
            .setCustomArgumentResolvers(pageableArgumentResolver)
            .setControllerAdvice(exceptionTranslator)
            .setConversionService(createFormattingConversionService())
            .setMessageConverters(jacksonMessageConverter).build();
    }

    @Test
    void directPrefetch_ReturnSuccess() throws Exception {
        // given
        mockPrefetchResponse();

        // when
        performPrefetchWithContentAndExpectOk(PREFETCH_REQUEST_DTO);

        // then
        verifyPrefetch(PREFETCH_REQUEST_DTO);
    }

    @Test
    void directPrefetch_MaxNumberOfJtagResponses_ReturnSuccess() throws Exception {
        // given
        mockPrefetchResponse();

        // when
        performPrefetchWithContentAndExpectOk(PREFETCH_REQUEST_DTO_MAX_NUMBER_OF_RESPONSES);

        // then
        verifyPrefetch(PREFETCH_REQUEST_DTO_MAX_NUMBER_OF_RESPONSES);
    }

    @Test
    void directPrefetch_TooManyJtagResponses_ReturnsBadRequest() throws Exception {
        // when
        performPrefetchWithContentAndExpectBadRequest(PREFETCH_REQUEST_DTO_TOO_MANY_RESPONSES);

        // then
        verifyNothingHappened();
    }

    @Test
    void directPrefetch_NoApiVersion_ReturnsBadRequest() throws Exception {
        // when
        performPrefetchWithContentAndExpectBadRequest(PREFETCH_REQUEST_DTO_NO_API_VERSION);

        // then
        verifyNothingHappened();
    }

    @Test
    void pufActivate_ReturnSuccess() throws Exception {
        // given
        mockPufActivateResponse();

        // when
        performPufActivateWithContentAndExpectOk(PUF_ACTIVATE_REQUEST_DTO);

        // then
        verifyPufActivate(PUF_ACTIVATE_REQUEST_DTO);
    }

    private void mockPrefetchResponse() {
        when(onboardingService.directPrefetch(any())).thenReturn(PREFETCH_RESPONSE_DTO);
    }

    private void mockPufActivateResponse() {
        when(onboardingService.pufActivate(any())).thenReturn(PUF_ACTIVATE_RESPONSE_DTO);
    }

    private void performPrefetchWithContentAndExpectBadRequest(DirectPrefetchRequestDTO request) throws Exception {
        performPrefetchWithContentAndExpectBadRequest(new String(convertObjectToJsonBytes(request)));
    }

    private void performPrefetchWithContentAndExpectBadRequest(String request) throws Exception {
        performWithContentAndExpectBadRequest(PREFETCH_NEXT, request);
    }

    private void performPrefetchWithContentAndExpectOk(DirectPrefetchRequestDTO request) throws Exception {
        performWithContentAndExpectOk(PREFETCH_NEXT, request, PREFETCH_RESPONSE_DTO);
    }

    private void performPufActivateWithContentAndExpectOk(PufActivateRequestDTO request) throws Exception {
        performWithContentAndExpectOk(PUF_ACTIVATE, request, PUF_ACTIVATE_RESPONSE_DTO);
    }

    private void performWithContentAndExpectOk(String resource, Object request, Object response) throws Exception {
        restMockMvc.perform(post(resource)
                .contentType(APPLICATION_JSON_UTF8)
                .content(convertObjectToJsonBytes(request)))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
            .andExpect(content().bytes(convertObjectToJsonBytes(response)));
    }

    private void performWithContentAndExpectBadRequest(String resource, String request) throws Exception {
        restMockMvc.perform(post(resource)
                .contentType(APPLICATION_JSON_UTF8)
                .content(request))
            .andExpect(status().isBadRequest())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
            .andExpect(jsonPath("$.status.code").value(ErrorCodeMap.INVALID_FIELDS_IN_PAYLOAD.getCode()))
            .andExpect(jsonPath("$.status.message").value(ErrorCodeMap.INVALID_FIELDS_IN_PAYLOAD.getExternalMessage()));
    }

    private void verifyNothingHappened() {
        verifyNoInteractions(onboardingService);
    }

    private void verifyPrefetch(DirectPrefetchRequestDTO expectedDTO) {
        final var requestDTOCaptor = ArgumentCaptor.forClass(DirectPrefetchRequestDTO.class);
        verify(onboardingService).directPrefetch(requestDTOCaptor.capture());

        final var actualDTO = requestDTOCaptor.getValue();
        assertEquals(expectedDTO.getApiVersion(), actualDTO.getApiVersion());
        assertEquals(expectedDTO.getSupportedCommands(), actualDTO.getSupportedCommands());
        assertEquals(expectedDTO.getJtagResponses().size(), actualDTO.getJtagResponses().size());
    }

    private void verifyPufActivate(PufActivateRequestDTO expectedDTO) {
        final var requestDTOCaptor = ArgumentCaptor.forClass(PufActivateRequestDTO.class);
        verify(onboardingService).pufActivate(requestDTOCaptor.capture());

        final var actualDTO = requestDTOCaptor.getValue();
        assertEquals(expectedDTO.getPufType(), actualDTO.getPufType());
        assertEquals(expectedDTO.getContext().getValue(), actualDTO.getContext().getValue());
        assertEquals(expectedDTO.getApiVersion(), actualDTO.getApiVersion());
        assertEquals(expectedDTO.getSupportedCommands(), actualDTO.getSupportedCommands());
        assertEquals(expectedDTO.getJtagResponses().size(), actualDTO.getJtagResponses().size());
    }

}
