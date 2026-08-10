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

package com.intel.bkp.bkps.connector;

import com.intel.bkp.bkps.config.ApplicationProperties;
import com.intel.bkp.fpgacerts.dp.IDistributionPointConnector;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.net.MalformedURLException;
import java.net.URL;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class DpConnector implements IDistributionPointConnector {

    private final RestTemplate distributionPointRestTemplate;
    private final ApplicationProperties applicationProperties;

    public Optional<byte[]> tryGetBytes(String url) {
        Optional<byte[]> responseBody = Optional.empty();
        try {
            URL originalUrl = new URL(url);
            String originalDomain = originalUrl.getProtocol() + "://" + originalUrl.getAuthority();
            URL expectedUrl = new URL(applicationProperties.getDistributionPoint().getMainPath());
            String expectedDomain = expectedUrl.getProtocol() + "://" + expectedUrl.getAuthority();
            String validUrl = url;
            // Replace only if the domains are different
            if (!originalDomain.equals(expectedDomain)) {
                validUrl = originalUrl.toString().replaceFirst(originalDomain, expectedDomain);
            }
            log.info("Performing request to: {}", validUrl);
            final ResponseEntity<byte[]> response = distributionPointRestTemplate.getForEntity(validUrl, byte[].class);

            if (response.getStatusCode().is2xxSuccessful()) {
                log.debug("Request status code: {}", response.getStatusCode());
                responseBody = Optional.ofNullable(response.getBody());
            } else {
                log.error("Request status code: {}", response.getStatusCode());
            }
        } catch (MalformedURLException urlException) {
            log.error("URL path \"%s\" to be fetched is malformed.".formatted(url), urlException);
            return Optional.empty();
        } catch (Exception e) {
            log.error("Failed to get http response.", e);
        }
        return responseBody;
    }
}
