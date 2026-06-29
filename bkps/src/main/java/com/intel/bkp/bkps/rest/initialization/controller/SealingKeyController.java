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

package com.intel.bkp.bkps.rest.initialization.controller;

import com.intel.bkp.bkps.rest.initialization.InitializationResource;
import com.intel.bkp.bkps.rest.initialization.model.dto.EncryptedSealingKeyDTO;
import com.intel.bkp.bkps.rest.initialization.model.dto.SealingKeyResponseDTO;
import com.intel.bkp.bkps.rest.initialization.service.SealingKeyService;
import com.intel.bkp.core.exceptions.ApplicationError;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static com.intel.bkp.core.utils.ApplicationConstants.REQUEST_BODY_STRING_MAX_SIZE;

@RestController
@Validated
@RequestMapping(InitializationResource.SEALING_KEY_BASE)
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class SealingKeyController {

    private final SealingKeyService sealingKeyService;

    @Operation(
        summary = "Create BKP Service Sealing Key",
        description = "This is a symmetric key used for wrapping all sensitive "
            + "information before it is stored in the database.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "400", description = "Client error. See response body for details.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class))),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @PostMapping
    public synchronized void createSealingKey() {
        sealingKeyService.createSealingKey();
    }

    @Operation(
        summary = "Rotate BKP Service Sealing Key",
        description = "This request rotates BKP Service Sealing Key. The new key is created and the old one is set "
            + "as disabled. After that all configurations are re-encrypted automatically with the new key.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "400", description = "Client error. See response body for details.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class))),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @PostMapping(InitializationResource.SEALING_KEY_ROTATE)
    public synchronized void rotateSealingKey() {
        sealingKeyService.rotateSealingKey();
    }

    @Operation(
        summary = "List BKP Service Sealing Keys",
        description = "This is the request to list all BKP Service Sealing Keys.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "400", description = "Client error. See response body for details.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class))),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @GetMapping
    public synchronized List<SealingKeyResponseDTO> listSealingKeys() {
        return sealingKeyService.getAllSealingKeys();
    }

    @Operation(
        summary = "Backup Configurations",
        description =
            "This request performs backup of all existing configurations by reencrypting them with new Sealing Key "
                + "('Backup Key') created in memory. The request requires RSA Import Pub Key in pem file format which "
                + "can be obtained using Get BKP Service Import Public Key API. The service uses the RSA key to "
                + "encrypt "
                + "Backup Key and returns the encrypted bytes encoded to Base64 format.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "400",
                         description = "Incorrect request data. For details see 'status' in the response body",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class))),
            @ApiResponse(responseCode = "500", description = "Internal error occurred. Contact support.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @PostMapping(InitializationResource.SEALING_KEY_BACKUP)
    public synchronized ResponseEntity<EncryptedSealingKeyDTO> backupServiceConfigurations(
        @RequestBody @Valid @Size(max = REQUEST_BODY_STRING_MAX_SIZE) String rsaImportPubKeyPem) {
        log.debug("REST request to backup all ServiceConfigurations.");
        EncryptedSealingKeyDTO encryptedSealingKeyDTO = sealingKeyService.backup(rsaImportPubKeyPem);
        return ResponseEntity.ok(encryptedSealingKeyDTO);
    }

    @Operation(
        summary = "Restore Configurations",
        description =
            "This request restores all existing configurations by importing 'Backup Key' to new security enclave. "
                + "The request requires encrypted Backup Key in Base64 encoded format which can be obtained "
                + "by calling Backup API.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "400",
                         description = "Incorrect request data. For details see 'status' in the response body",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class))),
            @ApiResponse(responseCode = "500", description = "Internal error occurred. Contact support.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @PostMapping(InitializationResource.SEALING_KEY_RESTORE)
    public synchronized void restoreServiceConfigurations(
        @RequestBody @Valid @NotNull EncryptedSealingKeyDTO encryptedSealingKeyDTO) {
        log.debug("REST request to restore ServiceConfigurations.");
        sealingKeyService.restore(encryptedSealingKeyDTO.getEncryptedSealingKey());
    }


}
