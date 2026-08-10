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

package com.intel.bkp.bkps.rest.configuration.controller;

import com.intel.bkp.bkps.rest.configuration.ConfigurationResource;
import com.intel.bkp.bkps.rest.configuration.service.ImportKeyService;
import com.intel.bkp.bkps.rest.initialization.InitializationResource;
import com.intel.bkp.core.exceptions.ApplicationError;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

/**
 * REST controller for managing ImportKey.
 */
@RestController
@Validated
@RequestMapping(ConfigurationResource.CONFIG_NODE)
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class ImportKeyController {

    private final ImportKeyService importKeyService;

    @Operation(
        summary = "Get BKP Service Import Public Key",
        description = "This request returns BKP Service Import Public Key in PEM format. "
            + "This key shall be used to encrypt Customer Confidential key before it is imported via "
            + "'Create New Configuration' API call when confidentialKey.mode is set to 'ENCRYPTED'.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "404", description = "The key does not exist."),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))
        })
    @GetMapping(InitializationResource.IMPORT_KEY)
    public ResponseEntity<String> getImportPublicKey() {
        long result = Instant.now().toEpochMilli();
        String resultFileName = "bkps_service_import_key_pub_" + result + ".pem";
        String contentType = MediaType.APPLICATION_OCTET_STREAM_VALUE;
        String importPublicKey = importKeyService.getServiceImportPublicKey();
        return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType(contentType))
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resultFileName + "\"")
            .body(importPublicKey);
    }
}
