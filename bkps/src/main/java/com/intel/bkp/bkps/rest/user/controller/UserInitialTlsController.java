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
import com.intel.bkp.bkps.rest.user.service.UserService;
import com.intel.bkp.bkps.rest.validator.FileRequired;
import com.intel.bkp.core.exceptions.ApplicationError;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.time.Instant;

import static lombok.AccessLevel.PACKAGE;

@RestController
@AllArgsConstructor(access = PACKAGE)
@ConditionalOnProperty(prefix = "application", name = "users.init-api-enabled")
public class UserInitialTlsController {

    private final UserService userService;

    @Operation(summary = "Initial user creation endpoint.",
               description =
                   "This request creates initial user. This request is available without client authentication. "
                       + "Request body for this request should be PEM encoded x509 self signed certificate. "
                       + "This request will be blocked when active and not expired user with ROLE_SUPER_ADMIN is set. "
                       + "Token necessary to add new account is available in service logs and it is renewed "
                       + "periodically.",
               responses = {
                   @ApiResponse(responseCode = "200", description = "Operation successful.",
                                content = @Content(mediaType = MediaType.APPLICATION_OCTET_STREAM_VALUE)),
                   @ApiResponse(responseCode = "400", description = "Client error. See response body for details.",
                                content = @Content(schema = @Schema(implementation = ApplicationError.class))),
                   @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                                content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @PostMapping(value = UserResource.CREATE_USER, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public synchronized ResponseEntity<String> create(@PathVariable @NotBlank @Size(min = 64, max = 64) String token,
                                                      @Valid @FileRequired @RequestParam MultipartFile file) {
        String certificate = userService.createUserInitial(token, file);

        long result = Instant.now().toEpochMilli();
        String csrFileName = "user_certificate_" + result + ".pem";
        String contentType = MediaType.APPLICATION_OCTET_STREAM_VALUE;
        return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType(contentType))
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + csrFileName + "\"")
            .body(certificate);
    }
}
