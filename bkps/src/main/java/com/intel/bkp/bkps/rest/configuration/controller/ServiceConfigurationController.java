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

import com.intel.bkp.bkps.exception.ServiceConfigurationNotFound;
import com.intel.bkp.bkps.rest.configuration.ConfigurationResource;
import com.intel.bkp.bkps.rest.configuration.model.dto.ServiceConfigurationDTO;
import com.intel.bkp.bkps.rest.configuration.model.dto.ServiceConfigurationDetailsDTO;
import com.intel.bkp.bkps.rest.configuration.model.dto.ServiceConfigurationResponseDTO;
import com.intel.bkp.bkps.rest.configuration.model.mapper.ServiceConfigurationMapper;
import com.intel.bkp.bkps.rest.configuration.service.ServiceConfigurationService;
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

import static com.intel.bkp.bkps.rest.configuration.ConfigurationResource.CONFIGURATION;
import static com.intel.bkp.bkps.rest.configuration.ConfigurationResource.CONFIGURATION_DETAIL;

/**
 * REST controller for managing ServiceConfiguration.
 */
@RestController
@Validated
@RequestMapping(ConfigurationResource.CONFIG_NODE)
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class ServiceConfigurationController {

    private static final String ENTITY_NAME = "Configuration";

    private final ServiceConfigurationService serviceConfigurationService;
    private final ServiceConfigurationMapper serviceConfigurationMapper;

    @Operation(
        summary = "Create New Configuration",
        description = "This request creates new configuration in the BKP Service. "
            + "Each configuration has its own identifier returned by this call. "
            + "Configuration identifier is used by BKP Programmer during provisioning process to determine "
            + "settings for the device. If 'overbuildMax' is not provided it is set to -1 which indicates unlimited "
            + "number of provision operations. If importMode is set to 'ENCRYPTED', aesKey.value and "
            + "eFusesPriv.value shall be encrypted with BKPS Import Key. Required fields are marked with *.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "400",
                         description = "Incorrect request data. For details see 'status' in the response body"),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @PostMapping(CONFIGURATION)
    public synchronized ResponseEntity<ServiceConfigurationResponseDTO> createServiceConfiguration(
        @Valid @RequestBody ServiceConfigurationDTO serviceConfigurationDTO) throws URISyntaxException {
        log.debug("REST request to save ServiceConfiguration : {}", serviceConfigurationDTO);
        if (serviceConfigurationDTO.getId() != null) {
            throw new BKPBadRequestException(ErrorCodeMap.CREATE_ID_EXISTS_RESTRICTION);
        }

        ServiceConfigurationDTO saved = serviceConfigurationService.save(serviceConfigurationDTO);
        ServiceConfigurationResponseDTO result = serviceConfigurationMapper.toResultDto(saved);
        return ResponseEntity.created(new URI(CONFIGURATION + result.getId()))
            .headers(HeaderUtil.createEntityCreationAlert(ENTITY_NAME, result.getId().toString()))
            .body(result);
    }

    @Operation(
        summary = "Update configuration",
        description = "This request updates the configuration. "
            + "It may be used when blacklists or the overbuild protection counter need the update. "
            + "For overbuild protection counter setting a value which is equal or lower than current "
            + "counter value disables provisioning functionality. ",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "400", description = "Client error. See response body for details."),
            @ApiResponse(responseCode = "404", description = "Specified configuration does not exist."),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))
        })
    @PutMapping(CONFIGURATION_DETAIL)
    public synchronized ResponseEntity<ServiceConfigurationResponseDTO> updateServiceConfiguration(
        @Valid @RequestBody ServiceConfigurationDTO serviceConfigurationDTO, @PathVariable Long id) {
        log.debug("REST request to update ServiceConfiguration with id: {}", id);

        if (!serviceConfigurationService.exists(id)) {
            throw new ServiceConfigurationNotFound();
        }

        serviceConfigurationDTO.setId(id);

        ServiceConfigurationDTO saved = serviceConfigurationService.save(serviceConfigurationDTO);
        ServiceConfigurationResponseDTO result = serviceConfigurationMapper.toResultDto(saved);
        return ResponseEntity.ok()
            .headers(HeaderUtil.createEntityUpdateAlert(ENTITY_NAME, serviceConfigurationDTO.getId().toString()))
            .body(result);
    }

    @Operation(
        summary = "Get configurations",
        description = "This request returns a JSON list of all existing configurations.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))
        })
    @GetMapping(CONFIGURATION)
    public List<ServiceConfigurationResponseDTO> getAllServiceConfigurations() {
        log.debug("REST request to get all ServiceConfigurations");
        return serviceConfigurationService.findAllForResponse();
    }

    @Operation(
        summary = "Get configuration",
        description = "This request returns a JSON object representing details of specified configuration. "
            + "If overbuild max counter is set to unlimited the 'overbuild.max' returns -1.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "404", description = "Specified configuration does not exist."),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))
        })
    @GetMapping(CONFIGURATION_DETAIL)
    public ResponseEntity<ServiceConfigurationDetailsDTO> getServiceConfiguration(@PathVariable Long id) {
        log.debug("REST request to get ServiceConfiguration : {}", id);
        Optional<ServiceConfigurationDetailsDTO> serviceCfgDetailsDTO = serviceConfigurationService
            .findOneForDetails(id);
        return serviceCfgDetailsDTO.map(response -> ResponseEntity.ok().body(response))
            .orElseThrow(ServiceConfigurationNotFound::new);
    }

    @Operation(summary = "Delete Configuration",
               description = "This request deletes specified configuration",
               responses = {
                   @ApiResponse(responseCode = "200", description = "Operation successful."),
                   @ApiResponse(responseCode = "404", description = "Specified configuration does not exist."),
                   @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                                content = @Content(schema = @Schema(implementation = ApplicationError.class)))
               })
    @DeleteMapping(CONFIGURATION_DETAIL)
    public synchronized ResponseEntity<Void> deleteServiceConfiguration(@PathVariable Long id) {
        log.debug("REST request to delete ServiceConfiguration : {}", id);
        serviceConfigurationService.delete(id);
        return ResponseEntity.ok()
            .headers(HeaderUtil.createEntityDeletionAlert(ENTITY_NAME, String.valueOf(id))).build();
    }
}
