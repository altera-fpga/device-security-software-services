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

package com.intel.bkp.bkps.rest.onboarding.controller;

import com.intel.bkp.bkps.exception.PrefetchingGenericException;
import com.intel.bkp.bkps.exception.PrefetchingStatusFailed;
import com.intel.bkp.bkps.exception.PufActivationGenericException;
import com.intel.bkp.bkps.exception.SetAuthorityGenericException;
import com.intel.bkp.bkps.rest.onboarding.OnboardingResource;
import com.intel.bkp.bkps.rest.onboarding.model.DirectPrefetchRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.DirectPrefetchResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.PrefetchStatusRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.PrefetchStatusResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.PufActivateRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.PufActivateResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.service.OnboardingService;
import com.intel.bkp.core.exceptions.ApplicationError;
import com.intel.bkp.core.exceptions.BKPRuntimeException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static lombok.AccessLevel.PACKAGE;

@RestController
@Validated
@AllArgsConstructor(access = PACKAGE)
@Slf4j
public class OnboardingController {

    private final OnboardingService onboardingService;

    @Operation(
        summary = "Issue direct prefetching.",
        description =
            """
                It is used to cache required zip files in Provisioning Service DB, so it could be available \
                from Customer’s infrastructure for the following actions \
                (PUF Activation and Certificate provisioning to the device)

                This can be triggerred directly using Quartus PGM i.e. by customer’s contractor:
                quartus_pgm -c <cable=1> -m <mode=jtag> --bkp_options=<bkp_options> --bkp_prefetch
                """,
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "400", description = "Client error. See response body for details.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class))),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @PostMapping(OnboardingResource.PREFETCH_NEXT)
    public ResponseEntity<DirectPrefetchResponseDTO> directPrefetch(@Valid @RequestBody DirectPrefetchRequestDTO dto) {
        log.debug("Query direct prefetching with dto: {}", dto);

        try {
            return ResponseEntity.ok(onboardingService.directPrefetch(dto));
        } catch (BKPRuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new PrefetchingGenericException(e);
        }
    }

    @Operation(
        summary = "This request returns prefetching status",
        description = """
            Request params:
                1. if empty, it returns status of all prefetching actions scheduled in a queue
                2. if not empty, it returns prefetching status of pointed device
                    "familyID"  : "<2-character hex string, eg. 34>"
                    "uid"       : "<16-character hex string, eg. 0102030405060708>"
            """,
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "400", description = "Client error. See response body for details.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class))),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @GetMapping(OnboardingResource.PREFETCH_STATUS)
    public ResponseEntity<PrefetchStatusResponseDTO> prefetchStatus(@RequestParam(value = "familyId", required = false)
                                                                    String familyId,
                                                                    @RequestParam(value = "uid", required = false)
                                                                    String uid) {
        final PrefetchStatusRequestDTO dto = new PrefetchStatusRequestDTO(familyId, uid);
        log.debug("Query prefetching status with dto: {}", dto);

        try {
            return ResponseEntity.ok(onboardingService.prefetchStatus(dto));
        } catch (BKPRuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new PrefetchingStatusFailed(e);
        }
    }

    @Operation(
        summary = "Issue PUF Activate.",
        description =
            """
                It is used to activate PUF on a device using PUF Helper Data from previously cached zip file.

                PUF Activation can be done using Quartus PGM:
                quartus_pgm -c <cable=1> -m <mode=jtag> --bkp_options=<bkp_options> \
                --bkp_puf_activate --puf_type=<UDS_IID|UDS_INTEL>
                """,
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "400", description = "Client error. See response body for details.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class))),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @PostMapping(OnboardingResource.PUF_ACTIVATE)
    public ResponseEntity<PufActivateResponseDTO> pufActivate(@Valid @RequestBody PufActivateRequestDTO dto) {
        log.debug("Query PUF Activate with dto: {}", dto);

        try {
            return ResponseEntity.ok(onboardingService.pufActivate(dto));
        } catch (BKPRuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new PufActivationGenericException(e);
        }
    }

    @Operation(
        summary = "Issue SPDM Set Authority procedure.",
        description =
            """
                It is used to set Intel authority chain with suitable chain of certificates \
                issued by Intel per requested UDS type (efuse|puf): deviceID, enrollment and/or IID UDS.

                Certificate provisioning to the device can be done using Quartus PGM:
                quartus_pgm -c <cable=1> -m <mode=jtag> --bkp_options=<bkp_options> --bkp_set_authority \
                --puf_type=<UDS_EFUSE|UDS_IID|UDS_INTEL> --slot_id=<0..7>
                """,
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "400", description = "Client error. See response body for details.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class))),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @PostMapping(OnboardingResource.SET_AUTHORITY)
    public ResponseEntity<SetAuthorityResponseDTO> setAuthority(@Valid @RequestBody SetAuthorityRequestDTO dto) {
        log.debug("Query Set Authority with dto: {}", dto);

        try {
            return ResponseEntity.ok(onboardingService.setAuthority(dto));
        } catch (BKPRuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new SetAuthorityGenericException(e);
        }
    }
}
