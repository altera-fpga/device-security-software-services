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

package com.intel.bkp.bkps.testutils;

import com.intel.bkp.bkps.BkpsApp;
import com.intel.bkp.test.enumeration.ResourceDir;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.WebApplicationContext;

import java.net.URI;

import static com.intel.bkp.test.FileUtils.loadBinary;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

@ActiveProfiles(profiles = "staticbouncycastle")
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = BkpsApp.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@Slf4j
public abstract class IntegrationTestBase {

    private static final String DP_BASE_PATH = "https://pre1-tsci.dev.altera.com/content";

    @Autowired
    protected WebApplicationContext webApplicationContext;
    @Autowired
    protected RestTemplate distributionPointRestTemplate;
    protected MockRestServiceServer mockServerDistributionPoint;
    protected MockMvc mockMvc;

    protected void initMockServers() {
        mockServerDistributionPoint = MockRestServiceServer.createServer(distributionPointRestTemplate);
    }

    protected void mockResponse(URI uri, byte[] data) {
        mockServerDistributionPoint.expect(ExpectedCount.once(), requestTo(uri))
            .andExpect(method(HttpMethod.GET))
            .andRespond(withStatus(HttpStatus.OK).contentType(MediaType.APPLICATION_OCTET_STREAM).body(data));
    }

    protected void mockDpResponse(String... paths) throws Exception {
        for (String path : paths) {
            final URI uri = new URI(DP_BASE_PATH + path);
            final String fileName = getFilenameFromPath(uri);
            mockResponse(uri, loadBinary(ResourceDir.ROOT, fileName));
        }
    }

    protected void mockDpNotValidResponse(String... paths) throws Exception {
        for (String path : paths) {
            final URI uri = new URI(DP_BASE_PATH + path);
            mockServerDistributionPoint.expect(requestTo(uri))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withStatus(HttpStatus.NOT_FOUND)
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                );
        }
    }

    private String getFilenameFromPath(URI uri) {
        final String uriPath = uri.getPath();
        return uriPath.substring(uriPath.lastIndexOf('/') + 1);
    }
}
