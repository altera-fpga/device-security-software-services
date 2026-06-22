/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2025 Altera Corporation. All Rights Reserved.
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

package com.intel.bkp.bkps.rest.initialization.controller;

import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.initialization.InitializationResource;
import com.intel.bkp.bkps.rest.initialization.model.dto.SigningKeyDTO;
import com.intel.bkp.bkps.rest.initialization.model.dto.SigningKeyResponseDTO;
import com.intel.bkp.bkps.rest.initialization.service.SigningKeyService;
import com.intel.bkp.bkps.rest.validator.FileRequired;
import com.intel.bkp.core.exceptions.ApplicationError;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.PublicKeyHelperException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

import static com.intel.bkp.utils.HexConverter.toHex;

@RestController
@Validated
@RequestMapping(InitializationResource.INIT_NODE)
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class SigningKeyController {

    private final SigningKeyService signingKeyService;

    @Operation(
        summary = "Create BKP Service Signing Key",
        description = "This request generates BKP Service Signing Key.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "400", description = "Client error. See response body for details.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class))),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @PostMapping(InitializationResource.SIGNING_KEY)
    public synchronized ResponseEntity<SigningKeyDTO> createSigningKey() {
        return ResponseEntity.ok(signingKeyService.createSigningKey());
    }

    @Operation(
        summary = "List all Signing Keys",
        description = "This request returns a JSON list of all existing signing keys.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @GetMapping(InitializationResource.SIGNING_KEY_LIST)
    public List<SigningKeyResponseDTO> getAllSigningKeys() {
        return signingKeyService.getAllSigningKeys();
    }

    @Operation(
        summary = "Get BKP Service Signing Public Key in PSG format",
        description = "This request returns BKP Service Signing Public Key in PSG format encoded with base64.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "404", description = "The key does not exist.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class))),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @GetMapping(InitializationResource.SIGNING_KEY_PUB_KEY)
    public ResponseEntity<String> getSigningKey(@PathVariable Long signingKeyId) {
        long result = Instant.now().toEpochMilli();
        String resultFileName = "bkps_signing_key_pub_" + result + ".txt";
        String contentType = MediaType.APPLICATION_OCTET_STREAM_VALUE;
        String signingKeyPublicPart = signingKeyService.getSigningKeyPublicPart(signingKeyId);
        return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType(contentType))
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resultFileName + "\"")
            .body(signingKeyPublicPart);
    }

    @Operation(summary = "Activate Service Signing Key",
               responses = {
                   @ApiResponse(responseCode = "200", description = "Operation successful."),
                   @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                                content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @PostMapping(InitializationResource.SIGNING_KEY_ACTIVATE)
    public synchronized void activateSigningKey(@PathVariable Long signingKeyId) {
        signingKeyService.activateSigningKey(signingKeyId);
    }

    @Operation(
        summary = "Add Product Owner Root Signing Public Key in QKY Format",
        description = "This request adds Product Owner/Customer Root Signing Public Key in QKY format.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "400", description = "Client error. See response body for details.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class))),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @PostMapping(value = InitializationResource.ROOT_SIGNING_KEY, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public synchronized void createRootSigningPublicKeyInQkyFormat(@Valid @FileRequired
                                                                   @RequestParam MultipartFile file) {
        try {
            signingKeyService.addRootSigningPublicKey(toHex(file.getBytes()));
        } catch (IOException e) {
            throw new BKPBadRequestException(ErrorCodeMap.FAILED_TO_PARSE_ROOT_PUBLIC_KEY);
        }
    }

    @Operation(
        summary = "Upload BKP Service Signing Key in QKY Format",
        description = "This request uploads BKP Service Signing Key Chain in QKY Format."
            + "This certificate chain is rooted in the Product Owner Root Signing Key and has maximum 3 elements "
            + "(including root and leaf certificate). "
            + "The chain is parsed by the service and checked against Product Owner Root Signing Public Key.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "400", description = "Client error. See response body for details.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class))),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @PostMapping(value = InitializationResource.SIGNING_KEY_UPLOAD, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public synchronized void uploadSigningKey(@PathVariable Long signingKeyId,
                                              @Valid @FileRequired @RequestParam MultipartFile singleRootChain,
                                              @Valid @FileRequired @RequestParam MultipartFile multiRootChain) {
        try {
            signingKeyService.uploadSigningKeyChain(
                signingKeyId,
                toHex(singleRootChain.getBytes()),
                toHex(multiRootChain.getBytes())
            );
        } catch (IOException e) {
            throw new BKPBadRequestException(ErrorCodeMap.FAILED_TO_PARSE_ROOT_PUBLIC_KEY);
        } catch (PublicKeyHelperException e) {
            throw new RuntimeException(e);
        }
    }
}
