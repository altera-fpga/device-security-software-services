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

package com.intel.bkp.bkps.rest.onboarding.handler;

import com.intel.bkp.bkps.exception.ProgrammerResponseNumberException;
import com.intel.bkp.bkps.exception.PufActivationFamilyNotSupported;
import com.intel.bkp.bkps.exception.PufActivationGenericException;
import com.intel.bkp.bkps.exception.PufHelperDataNotFoundInCache;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.sigma.SupportedMessageTypesFactory;
import com.intel.bkp.bkps.programmer.utils.ProgrammerResponseToDataAdapter;
import com.intel.bkp.bkps.protocol.common.service.GetChipIdMessageSender;
import com.intel.bkp.bkps.protocol.common.service.GetIdCodeMessageSender;
import com.intel.bkp.bkps.rest.onboarding.model.DeviceId;
import com.intel.bkp.bkps.rest.onboarding.model.PufActivateRequestDTOReader;
import com.intel.bkp.bkps.rest.onboarding.model.PufActivateResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.PufActivateResponseDTOBuilder;
import com.intel.bkp.bkps.rest.onboarding.model.PufActivateTransferObject;
import com.intel.bkp.bkps.rest.prefetching.service.ZipPrefetchRepositoryService;
import com.intel.bkp.bkps.rest.provisioning.utils.ZipUtil;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.fpgacerts.model.Family;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

import static com.intel.bkp.bkps.domain.enumeration.FamilyExtended.FAMILIES_WITH_PUF_SUPPORTED;
import static com.intel.bkp.bkps.programmer.utils.ProgrammerResponsesNumberVerifier.verifyNumberOfResponses;

@Component
@Slf4j
@RequiredArgsConstructor
public class PufActivatePushDataComponent extends PufActivateHandler {

    private static final int EXPECTED_NUMBER_OF_RESPONSES = 2;
    private static final String ZIP_NOT_FOUND_IN_CACHE = "ZIP not found in cache.";
    private static final String PUF_HELPER_DATA_NOT_FOUND_IN_ZIP = "PUF Helper data not found in ZIP.";
    private static final String PUF_HELPER_DATA_FOUND_BUT_CANNOT_BE_EXTRACTED =
        "PUF Helper data found but cannot be extracted.";
    private static final String PUF_HELPDATA_NAME = "puf/pufhelper.puf";


    private final ZipPrefetchRepositoryService zipPrefetchRepositoryService;
    private final GetChipIdMessageSender getChipIdMessageSender;
    private final GetIdCodeMessageSender getIdCodeMessageSender;

    @Override
    public PufActivateResponseDTO handle(PufActivateTransferObject transferObject) {
        final PufActivateRequestDTOReader dtoReader = transferObject.getDtoReader();
        if (dtoReader.getJtagResponses().size() == EXPECTED_NUMBER_OF_RESPONSES) {
            return perform(dtoReader);
        }
        return successor.handle(transferObject);
    }

    private PufActivateResponseDTO perform(PufActivateRequestDTOReader dtoReader) {
        log.info(prepareLogEntry("parsing quartus responses..."));

        final List<ProgrammerResponse> jtagResponses = dtoReader.getJtagResponses();

        try {
            verifyNumberOfResponses(jtagResponses, EXPECTED_NUMBER_OF_RESPONSES);
        } catch (ProgrammerResponseNumberException e) {
            throw new PufActivationGenericException(e.getMessage());
        }

        final var adapter = new ProgrammerResponseToDataAdapter(jtagResponses);
        final String uid = getChipIdMessageSender.retrieve(adapter.getNext());
        final Family family = getIdCodeMessageSender.retrieve(adapter.getNext());
        final PufType pufType = PufType.fromOrdinal(dtoReader.getDto().getPufType());
        final DeviceId deviceId = DeviceId.instance(family, uid);

        log.info(prepareLogEntry("action will be performed for device: " + deviceId));
        log.info(prepareLogEntry("pufType: " + pufType));

        ensureFamilyIsSupported(deviceId);
        ensureZipIsPrefetched(deviceId);
        final byte[] pufHelperData = getPufHelperData(deviceId);

        return new PufActivateResponseDTOBuilder()
            .withMessages(List.of(getPushHelperDataCommand(pufType, pufHelperData)))
            .build();
    }

    private static void ensureFamilyIsSupported(DeviceId deviceId) {
        if (!familySupported(deviceId.getFamily())) {
            throw new PufActivationFamilyNotSupported(FAMILIES_WITH_PUF_SUPPORTED, deviceId.getFamily());
        }
    }

    private void ensureZipIsPrefetched(DeviceId deviceId) {
        if (!zipPrefetchRepositoryService.isZipPrefetched(deviceId)) {
            throw new PufHelperDataNotFoundInCache(ZIP_NOT_FOUND_IN_CACHE);
        }
    }

    private byte[] getPufHelperData(DeviceId deviceId) {
        final byte[] zip = zipPrefetchRepositoryService.find(deviceId)
            .orElseThrow(() -> new PufHelperDataNotFoundInCache(ZIP_NOT_FOUND_IN_CACHE));

        final List<String> zipContentFiles = ZipUtil.listZipContentFilenames(zip);
        log.debug("ZIP content listing: {}", zipContentFiles);

        if (fileNotPresentInZipContent(zipContentFiles, PUF_HELPDATA_NAME)) {
            throw new PufHelperDataNotFoundInCache(PUF_HELPER_DATA_NOT_FOUND_IN_ZIP);
        }

        return ZipUtil.extractFileFromZip(zip, PUF_HELPDATA_NAME)
            .orElseThrow(() -> new PufHelperDataNotFoundInCache(PUF_HELPER_DATA_FOUND_BUT_CANNOT_BE_EXTRACTED));
    }

    private static boolean fileNotPresentInZipContent(List<String> zipContentFiles, String fileName) {
        return zipContentFiles.stream().noneMatch(file -> file.endsWith(fileName));
    }

    private ProgrammerMessage getPushHelperDataCommand(PufType pufType, byte[] pufHelperData) {
        log.debug("Preparing PUSH_HELPER_DATA  ...");
        return ProgrammerMessage.from(
            SupportedMessageTypesFactory.getForPufActivate(pufType), pufHelperData);
    }

    private static boolean familySupported(Family family) {
        return FAMILIES_WITH_PUF_SUPPORTED.contains(family);
    }

}
