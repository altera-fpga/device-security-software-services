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

import com.intel.bkp.bkps.exception.CommandNotSupportedException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.exception.SpdmProcessIsStillRunning;
import com.intel.bkp.bkps.rest.provisioning.ProvisioningResource;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.service.ProvisioningService;
import com.intel.bkp.core.exceptions.ApplicationError;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static lombok.AccessLevel.PACKAGE;

@RestController
@Validated
@RequestMapping(ProvisioningResource.PROVISIONING_NODE)
@AllArgsConstructor(access = PACKAGE)
@Slf4j
public class ProvisioningController {

    private final ProvisioningService provisioningService;

    @Operation(
        summary = "Query get_next()",
        description = "This request uploads responses from Quartus. Body should contain context (may be empty), "
            + "configuration identifier (must match existing configuration in the service), BKP Programmer API "
            + "version, mask of commands supported by Quartus and list of responses. Returns list of commands with "
            + "corresponding command type, status of the communication, BKP Programmer API version and unchanged "
            + "provisioning context.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "400", description = "Client error. See response body for details.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class))),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @PostMapping(ProvisioningResource.GET_NEXT)
    public ResponseEntity<ProvisioningResponseDTO> getNext(@Valid @RequestBody ProvisioningRequestDTO dto) {
        log.debug("Query get_next() with request body: " + dto.toString());
        try {
            return ResponseEntity.ok(provisioningService.getNext(dto));
        } catch (ProvisioningGenericException | CommandNotSupportedException | SpdmProcessIsStillRunning e) {
            throw e;
        } catch (Exception e) {
            throw new ProvisioningGenericException(e);
        }
    }
}
