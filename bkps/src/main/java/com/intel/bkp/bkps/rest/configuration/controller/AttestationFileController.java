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

import com.intel.bkp.bkps.attestation.mapping.CacheCborMapper;
import com.intel.bkp.bkps.attestation.mapping.CacheCertificateMapper;
import com.intel.bkp.bkps.attestation.mapping.CacheCrlMapper;
import com.intel.bkp.bkps.domain.PrefetchEntity;
import com.intel.bkp.bkps.domain.enumeration.PrefetchEntityType;
import com.intel.bkp.bkps.repository.PrefetchRepository;
import com.intel.bkp.bkps.rest.configuration.ConfigurationResource;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.validator.FileRequired;
import com.intel.bkp.core.exceptions.ApplicationError;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.utils.CustomErrorCode;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FilenameUtils;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Path;

import static com.intel.bkp.bkps.rest.configuration.ConfigurationResource.ATTESTATION_FILE;

/**
 * REST controller for managing AttestationFile.
 */
@RestController
@Validated
@RequestMapping(ConfigurationResource.CONFIG_NODE)
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class AttestationFileController {

    private final PrefetchRepository prefetchRepository;

    @Operation(
        summary = "Upload attestation file",
        description = "This request uploads attestation files to BKPS and overwrites/adds to BKPS prefetch table. "
            + "BKPS prefetch table acts as a cache when running BKP Provisioning and Attestation flow. ",
        responses = {
            @ApiResponse(responseCode = "200", description = "Operation successful."),
            @ApiResponse(responseCode = "400",
                         description = "Incorrect request data. For details see 'status' in the response body"),
            @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                         content = @Content(schema = @Schema(implementation = ApplicationError.class)))})
    @PostMapping(value = ATTESTATION_FILE, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public synchronized ResponseEntity<Void> uploadAttestationFile(
        @RequestPart String path,
        @Valid @FileRequired @RequestPart MultipartFile file) {

        PrefetchEntityType fileType = getFileType(path);
        try {
            String fullUrlPath = Path.of(path).toUri().toString();
            log.info("Uploading file with full URL path:\n%s".formatted(fullUrlPath));
            switch (fileType) {
                case CORIM: {
                    CacheCborMapper mapper = new CacheCborMapper();
                    mapper.parse(file.getBytes())
                        .map(obj -> prefetchRepository.save(new PrefetchEntity(
                            fullUrlPath,
                            mapper.encode(obj),
                            PrefetchEntityType.CORIM)))
                        .orElseThrow();
                    break;
                }
                case CERT: {
                    CacheCertificateMapper mapper = new CacheCertificateMapper();
                    mapper.parse(file.getBytes())
                        .map(obj -> prefetchRepository.save(new PrefetchEntity(
                            fullUrlPath,
                            mapper.encode(obj),
                            PrefetchEntityType.CERT)))
                        .orElseThrow();
                    break;
                }
                case CRL: {
                    CacheCrlMapper mapper = new CacheCrlMapper();
                    mapper.parse(file.getBytes())
                        .map(obj -> prefetchRepository.save(new PrefetchEntity(
                            fullUrlPath,
                            mapper.encode(obj),
                            PrefetchEntityType.CRL)))
                        .orElseThrow();
                    break;
                }
                default: {
                    throw new BKPBadRequestException(new CustomErrorCode(ErrorCodeMap.UNSUPPORTED_FILETYPE_IN_PREFETCH,
                        String.format(ErrorCodeMap.UNSUPPORTED_FILETYPE_IN_PREFETCH.getExternalMessage(), fileType.name())));
                }
            }
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            throw new BKPBadRequestException(ErrorCodeMap.PARSE_ERROR_WHEN_UPLOADING);
        }
    }

    @Operation(summary = "Delete attestation file",
               description = "This request deletes attestation file from BKPS prefetch table.",
               responses = {
                   @ApiResponse(responseCode = "200", description = "Operation successful."),
                   @ApiResponse(responseCode = "404", description = "Specified path does not exist."),
                   @ApiResponse(responseCode = "500", description = "Internal error occurred.",
                                content = @Content(schema = @Schema(implementation = ApplicationError.class)))
               })
    @DeleteMapping(value = ATTESTATION_FILE, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public synchronized ResponseEntity<Void> deleteAttestationPolicy(@RequestPart String path) {
        log.debug("REST request to delete path {} from BKPS prefetch table", path);
        PrefetchEntityType fileType = getFileType(path);
        if (prefetchRepository.existsByPathContainingIgnoreCaseAndType(path, fileType)) {
            prefetchRepository.findByPathAndType(path, fileType)
                .ifPresent(entity -> prefetchRepository.delete(entity));
        } else {
            throw new BKPBadRequestException(ErrorCodeMap.PATH_NOT_EXIST_IN_PREFETCH);
        }
        return ResponseEntity.ok().build();
    }

    private PrefetchEntityType getFileType(String path) {
        String ext = FilenameUtils.getExtension(Path.of(path).toFile().getName());
        PrefetchEntityType fileType = null;
        try {
            fileType = PrefetchEntityType.valueOf(ext.toUpperCase());
        } catch (Exception e) {
            for (var type : PrefetchEntityType.values()) {
                // Look up for file type alike
                if (type.name().contains(ext.toUpperCase())) {
                    fileType = type;
                    break;
                }
            }
        }

        if (fileType == null) {
            throw new BKPBadRequestException(ErrorCodeMap.UNSUPPORTED_FILETYPE_IN_PREFETCH, ext);
        }
        return fileType;
    }
}
