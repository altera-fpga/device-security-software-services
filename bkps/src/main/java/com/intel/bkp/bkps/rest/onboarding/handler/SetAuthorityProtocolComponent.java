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

package com.intel.bkp.bkps.rest.onboarding.handler;

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmContextProviderImpl;
import com.intel.bkp.bkps.exception.ProgrammerResponseNumberException;
import com.intel.bkp.bkps.exception.SetAuthorityFamilyNotSupported;
import com.intel.bkp.bkps.exception.SetAuthorityGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.utils.ProgrammerResponseToDataAdapter;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.common.service.GetAttestationCertificateMessageSender;
import com.intel.bkp.bkps.protocol.common.service.GetChipIdMessageSender;
import com.intel.bkp.bkps.protocol.common.service.GetIdCodeMessageSender;
import com.intel.bkp.bkps.rest.onboarding.model.DeviceId;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityContext;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityRequestDTOReader;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityResponseDTOBuilder;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityTransferObject;
import com.intel.bkp.bkps.rest.onboarding.model.SpdmMessageDTO;
import com.intel.bkp.bkps.spdm.model.MessageFromQueueEmpty;
import com.intel.bkp.bkps.spdm.model.SpdmThreadError;
import com.intel.bkp.bkps.spdm.model.UnrecoverableMessageFromQueueEmpty;
import com.intel.bkp.bkps.spdm.service.SpdmBackgroundService;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.crypto.exceptions.X509CertificateParsingException;
import com.intel.bkp.crypto.x509.parsing.X509CertificateParser;
import com.intel.bkp.fpgacerts.model.Family;
import com.intel.bkp.fpgacerts.url.params.DiceEnrollmentParams;
import com.intel.bkp.fpgacerts.url.params.parsing.DiceEnrollmentParamsIssuerParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.bkps.domain.enumeration.FamilyExtended.FAMILIES_WITH_SET_AUTH_SUPPORTED;
import static com.intel.bkp.bkps.programmer.model.MessageType.SEND_PACKET;
import static com.intel.bkp.bkps.programmer.utils.ProgrammerResponsesNumberVerifier.verifyNumberOfResponses;

@Component
@Slf4j
@RequiredArgsConstructor
public class SetAuthorityProtocolComponent extends SetAuthorityHandler {

    private static final int EXPECTED_NUMBER_OF_RESPONSES = 4;
    private static final String ZIP_NOT_FOUND_IN_CACHE = "ZIP not found in cache.";

    private final GetChipIdMessageSender getChipIdMessageSender;
    private final GetIdCodeMessageSender getIdCodeMessageSender;
    private final GetAttestationCertificateMessageSender getAttestationCertificateMessageSender;
    private final SpdmBackgroundService spdmBackgroundService;
    private final CertificateChainProvider certificateChainProvider;
    private final AesGcmContextProviderImpl contextEncryptionProvider;

    @Override
    public SetAuthorityResponseDTO handle(SetAuthorityTransferObject transferObject) {
        final SetAuthorityContext context = transferObject.getDtoReader().getContext();
        if (context.getFlowStage() == FlowStage.SET_AUTHORITY_SESSION) {
            return perform(transferObject);
        }
        return successor.handle(transferObject);
    }

    private SetAuthorityResponseDTO perform(SetAuthorityTransferObject transferObject) {
        if (!spdmBackgroundService.isProcessing()) {
            throw new SetAuthorityGenericException("SPDM Service is not working.");
        }

        final SetAuthorityRequestDTOReader dtoReader = transferObject.getDtoReader();
        final SetAuthorityContext context = dtoReader.getContext();

        log.info(prepareLogEntry("parsing quartus responses..."));

        final List<ProgrammerResponse> jtagResponses = dtoReader.getJtagResponses();

        try {
            verifyNumberOfResponses(jtagResponses, EXPECTED_NUMBER_OF_RESPONSES);
        } catch (ProgrammerResponseNumberException e) {
            throw new SetAuthorityGenericException(e.getMessage());
        }

        final var adapter = new ProgrammerResponseToDataAdapter(jtagResponses);
        final String uid = getChipIdMessageSender.retrieve(adapter.getNext());
        final Family family = getIdCodeMessageSender.retrieve(adapter.getNext());

        final int slotId = context.getSlotId();
        final PufType pufType = context.getPufType();
        final DeviceId deviceId = DeviceId.instance(family, uid);
        final boolean forceEnrollment = context.isForceEnrollment();

        log.info(prepareLogEntry("action will be performed for device: " + deviceId));
        log.info(prepareLogEntry("pufType: " + pufType));
        log.info(prepareLogEntry("slotId: " + slotId));
        ensureFamilyIsSupported(deviceId);
        ensureZipIsPrefetched(deviceId);

        final byte[] enrollmentDeviceIdCertBytes = getAttestationCertificateMessageSender.retrieve(adapter.getNext())
            .orElseThrow(() -> new SetAuthorityGenericException("Enrollment Device ID cert does not exist."));

        final X509Certificate enrollmentDeviceIdCert =
            Optional.ofNullable(parseCertificate(enrollmentDeviceIdCertBytes))
                .orElseThrow(() -> new SetAuthorityGenericException("Enrollment Device ID cert is invalid."));

        final String svn = Optional.ofNullable(parseDiceEnrollmentParams(enrollmentDeviceIdCert))
            .map(DiceEnrollmentParams::getSvn)
            .orElseThrow(() -> new SetAuthorityGenericException(
                "Enrollment Device ID cert is invalid - missing SVN."));

        log.info(prepareLogEntry("svn: " + svn));

        spdmBackgroundService.pushResponseToQueue(new SpdmMessageDTO(adapter.getNext()));

        ensureLibspdmFinishedSuccessfully();

        final List<byte[]> certificateChain =
            certificateChainProvider.get(deviceId, pufType, svn, enrollmentDeviceIdCert, forceEnrollment)
                .orElseThrow(() -> new SetAuthorityGenericException(ZIP_NOT_FOUND_IN_CACHE));

        if (dtoReader.getContext().isMctpEncapsulateSupported()) {
            log.debug("SPDM VCA returned success.");
            spdmBackgroundService.startSetAuthority(certificateChain, slotId, true);
        } else {
            log.debug("SPDM VCA failed.");
            spdmBackgroundService.startSetAuthority(certificateChain, slotId, false);
        }


        try {
            final SpdmMessageDTO messageFromQueue = spdmBackgroundService.getMessageFromQueue();

            final List<ProgrammerMessage> programmerMessages = new ArrayList<>();
            programmerMessages.add(ProgrammerMessage.from(SEND_PACKET, messageFromQueue.getMessage()));

            context.setDeviceId(deviceId);
            context.setSvn(svn);
            context.setFlowStage(FlowStage.SET_AUTHORITY_CERTCHAIN);

            return new SetAuthorityResponseDTOBuilder()
                .context(context)
                .withMessages(programmerMessages)
                .encryptionProvider(contextEncryptionProvider)
                .build();
        } catch (EncryptionProviderException | IOException e) {
            throw new SetAuthorityGenericException("Preparing response failed.", e);
        } catch (UnrecoverableMessageFromQueueEmpty e) {
            throw new SetAuthorityGenericException("No response from SPDM Service.");
        }
    }

    private void ensureLibspdmFinishedSuccessfully() {
        try {
            final Optional<SpdmMessageDTO> messageFromQueue = spdmBackgroundService.tryGetMessageFromQueue();

            if (messageFromQueue.isPresent()) {
                throw new SetAuthorityGenericException("More messages from libspdm than expected: " + messageFromQueue);
            }

            final SpdmThreadError processResult = spdmBackgroundService.getProcessResult()
                .orElse(SpdmThreadError.FAILURE);

            log.debug("SPDM Service - process result: {}", processResult);

            if (!processResult.isSuccess()) {
                throw new SetAuthorityGenericException("SPDM Process failed with status: %s".formatted(processResult));
            }
        } catch (MessageFromQueueEmpty e) {
            throw new SetAuthorityGenericException("SPDM Service failed to complete gracefully.");
        }
    }

    private DiceEnrollmentParams parseDiceEnrollmentParams(X509Certificate x509Certificate) {
        log.debug("Parsing DICE Enrollment Params from cert: {}",
            x509Certificate.getSubjectX500Principal().getName());
        return DiceEnrollmentParamsIssuerParser.instance().parse(x509Certificate);
    }


    private static void ensureFamilyIsSupported(DeviceId deviceId) {
        if (!familySupported(deviceId.getFamily())) {
            throw new SetAuthorityFamilyNotSupported(FAMILIES_WITH_SET_AUTH_SUPPORTED, deviceId.getFamily());
        }
    }

    private void ensureZipIsPrefetched(DeviceId deviceId) {
        if (!certificateChainProvider.isAvailable(deviceId)) {
            throw new SetAuthorityGenericException(ZIP_NOT_FOUND_IN_CACHE);
        }
    }

    private static boolean familySupported(Family family) {
        return FAMILIES_WITH_SET_AUTH_SUPPORTED.contains(family);
    }

    private X509Certificate parseCertificate(byte[] cert) {
        try {
            log.debug("Parsing Enrollment DeviceID certificate.");
            return X509CertificateParser.toX509Certificate(cert);
        } catch (X509CertificateParsingException e) {
            return null;
        }
    }
}
