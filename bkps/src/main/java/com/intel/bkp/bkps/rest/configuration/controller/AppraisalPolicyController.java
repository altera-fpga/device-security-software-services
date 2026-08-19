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

import com.intel.bkp.bkps.exception.AppraisalPolicyNotFound;
import com.intel.bkp.bkps.rest.configuration.ConfigurationResource;
import com.intel.bkp.bkps.rest.configuration.model.dto.AppraisalPolicyDTO;
import com.intel.bkp.bkps.rest.configuration.model.dto.AppraisalPolicyResponseDTO;
import com.intel.bkp.bkps.rest.configuration.service.AppraisalPolicyService;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.util.HeaderUtil;
import com.intel.bkp.core.exceptions.ApplicationError;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.bkps.rest.configuration.ConfigurationResource.APPRAISAL_POLICY;
import static com.intel.bkp.bkps.rest.configuration.ConfigurationResource.APPRAISAL_POLICY_DETAIL;

/**
 * REST controller for managing AppraisalPolicy.
 */
@RestController
@Validated
@RequestMapping(ConfigurationResource.CONFIG_NODE)
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class AppraisalPolicyController {

    private static final String ENTITY_NAME = "Appraisal Policy";

    private final AppraisalPolicyService appraisalPolicyService;

    @Operation(
        summary = "Create New Appraisal Policy",
        description = "This request creates a new appraisal policy in the BKP Service. "
            + "Each appraisal policy has its own identifier returned by this call. "
            + "Appraisal policy identifier is used by BKPS during provisioning process to determine "
            + "appraisal policy for the configuration. If firmware version is provided in the appraisal policy, "
            + "BKPS shall validate it against the firmware version obtained from device measurements. "
            + "If design version is provided in the appraisal policy, BKPS shall validate it against the "
            + "design version obtained from the design measurements file (.CoRIM)",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "400",
                         description = "Incorrect request data. For details see 'status' in the response body"),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @PostMapping(APPRAISAL_POLICY)
    public synchronized ResponseEntity<AppraisalPolicyResponseDTO> createAppraisalPolicy(
        @Valid @RequestBody AppraisalPolicyDTO appraisalPolicyDTO) throws URISyntaxException {
        log.debug("REST request to save Appraisal Policy : {}", appraisalPolicyDTO);
        if (appraisalPolicyDTO.getId() != null) {
            throw new BKPBadRequestException(ErrorCodeMap.CREATE_ID_EXISTS_RESTRICTION);
        }

        var saved = appraisalPolicyService.save(appraisalPolicyDTO);
        return ResponseEntity.created(new URI(APPRAISAL_POLICY + saved.getId()))
            .headers(HeaderUtil.createEntityCreationAlert(ENTITY_NAME, saved.getId().toString()))
            .body(saved);
    }

    @Operation(
        summary = "Update appraisal policy",
        description = "This request updates the appraisal policy. ",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "400", description = "Client error. See response body for details."),
            @ApiResponse(responseCode = "404", description = "Specified policy does not exist."),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))
        })
    @PutMapping(APPRAISAL_POLICY_DETAIL)
    public synchronized ResponseEntity<AppraisalPolicyResponseDTO> updateAppraisalPolicy(
        @Valid @RequestBody AppraisalPolicyDTO appraisalPolicyDTO, @PathVariable Long id) {
        log.debug("REST request to update Appraisal Policy with id: {}", id);

        if (!appraisalPolicyService.exists(id)) {
            throw new AppraisalPolicyNotFound();
        }

        appraisalPolicyDTO.setId(id);

        var saved = appraisalPolicyService.save(appraisalPolicyDTO);
        return ResponseEntity.ok()
            .headers(HeaderUtil.createEntityUpdateAlert(ENTITY_NAME, appraisalPolicyDTO.getId().toString()))
            .body(saved);
    }

    @Operation(
        summary = "Get appraisal policies",
        description = "This request returns a JSON list of all existing policies.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))
        })
    @GetMapping(APPRAISAL_POLICY)
    public List<AppraisalPolicyResponseDTO> getAllAppraisalPolicies() {
        log.debug("REST request to get all Appraisal Policies");
        return appraisalPolicyService.findAllForResponse();
    }

    @Operation(
        summary = "Get appraisal policy",
        description = "This request returns a JSON object representing details of specified policy. ",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "404", description = "Specified policy does not exist."),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))
        })
    @GetMapping(APPRAISAL_POLICY_DETAIL)
    public ResponseEntity<String> getAppraisalPolicy(@PathVariable Long id) {
        log.debug("REST request to get Appraisal Policy : {}", id);
        Optional<String> dto = appraisalPolicyService.findOneForDetails(id);
        return dto.map(response -> ResponseEntity.ok(response))
            .orElseThrow(AppraisalPolicyNotFound::new);
    }

    @Operation(summary = "Delete Appraisal Policy",
               description = "This request deletes specified policy.",
               responses = {
                   @ApiResponse(responseCode = "200", description = "Operation successful."),
                   @ApiResponse(responseCode = "404", description = "Specified policy does not exist."),
                   @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                                content = @Content(schema = @Schema(implementation = ApplicationError.class)))
               })
    @DeleteMapping(APPRAISAL_POLICY_DETAIL)
    public synchronized ResponseEntity<Void> deleteAppraisalPolicy(@PathVariable Long id) {
        log.debug("REST request to delete Appraisal Policy : {}", id);
        appraisalPolicyService.delete(id);
        return ResponseEntity.ok()
            .headers(HeaderUtil.createEntityDeletionAlert(ENTITY_NAME, String.valueOf(id))).build();
    }
}
