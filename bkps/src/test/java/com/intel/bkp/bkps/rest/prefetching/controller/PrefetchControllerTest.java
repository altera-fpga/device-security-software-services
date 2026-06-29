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

package com.intel.bkp.bkps.rest.prefetching.controller;

import com.intel.bkp.bkps.rest.RestUtil;
import com.intel.bkp.bkps.rest.prefetching.PrefetchResource;
import com.intel.bkp.bkps.rest.prefetching.model.IndirectPrefetchRequestDTO;
import com.intel.bkp.bkps.rest.prefetching.service.IndirectPrefetchService;
import com.intel.bkp.test.RandomUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class PrefetchControllerTest {

    private static final String ENDPOINT = PrefetchResource.PREFETCH_DEVICES_NODE;

    @Mock
    private IndirectPrefetchService indirectPrefetchService;

    @InjectMocks
    private PrefetchController prefetchController;

    private MockMvc mockMvc;

    @BeforeEach
    void setup() {
        this.mockMvc = MockMvcBuilders.standaloneSetup(prefetchController).build();
    }

    @Test
    void prefetchDevices() throws Exception {
        // given
        final int devicesNum = 5;
        final List<IndirectPrefetchRequestDTO> devices = new ArrayList<>();
        for (int inc = 0; inc < devicesNum; inc++) {
            final var prefetchDto = new IndirectPrefetchRequestDTO();
            prefetchDto.setUid(RandomUtils.generateDeviceIdHex());
            devices.add(prefetchDto);
        }

        // when
        mockMvc.perform(post(ENDPOINT)
                .contentType(RestUtil.APPLICATION_JSON_UTF8)
                .content(RestUtil.convertObjectToJsonBytes(devices)))
            .andExpect(status().isOk());

        // then
        verify(indirectPrefetchService).prefetchDevices(devices);
    }

    @Test
    void testPrefetchDevices_WithEmptyPayload_RespondWithBadRequest() throws Exception {
        // given
        final MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
            .post(ENDPOINT)
            .contentType(RestUtil.APPLICATION_JSON_UTF8);

        // when-then
        mockMvc.perform(requestBuilder)
            .andExpect(status().isBadRequest());
    }
}
