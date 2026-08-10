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

package com.intel.bkp.bkps.rest.user.controller;

import com.intel.bkp.bkps.rest.user.UserResource;
import com.intel.bkp.bkps.rest.user.model.dto.DynamicCertificateDTO;
import com.intel.bkp.bkps.rest.user.service.ServiceRootCertificateService;
import com.intel.bkp.bkps.rest.validator.FileRequired;
import com.intel.bkp.core.exceptions.ApplicationError;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

import static lombok.AccessLevel.PACKAGE;

@RestController
@RequestMapping(UserResource.USER_NODE)
@AllArgsConstructor(access = PACKAGE)
public class ServiceRootCertificateController {

    private final ServiceRootCertificateService serviceRootCertificateService;

    @Operation(summary = "Trusted certificate import",
               description = "This request imports trusted communication certificates to truststore. "
                   + "Imported certificates allows to communicate between components.",
               responses = {
                   @ApiResponse(responseCode = "200", description = "Operation successful.",
                                content = @Content(mediaType = MediaType.APPLICATION_OCTET_STREAM_VALUE)),
                   @ApiResponse(responseCode = "400", description = "Client error. See response body for details.",
                                content = @Content(schema = @Schema(implementation = ApplicationError.class))),
                   @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                                content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @PostMapping(value = UserResource.CERTIFICATE_MANAGE_NODE, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public synchronized void importServiceRootCertificate(@Valid @FileRequired @RequestParam MultipartFile file) {
        serviceRootCertificateService.rootCertificateImport(file);
    }

    @Operation(
        summary = "List all trusted communication certificates imported to truststore",
        description = "This request returns a list of imported certificates to truststore.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @GetMapping(UserResource.CERTIFICATE_MANAGE_NODE)
    public List<DynamicCertificateDTO> listServiceRootCertificates() {
        return serviceRootCertificateService.getAll();
    }

    @Operation(
        summary = "Delete imported service communication certificate",
        description = "This request deletes certificate.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "404", description = "Client error. See response body for details.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class))),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @DeleteMapping(UserResource.CERTIFICATE_DELETE)
    public synchronized void deleteServiceRootCertificate(@PathVariable String alias) {
        serviceRootCertificateService.delete(alias);
    }
}
