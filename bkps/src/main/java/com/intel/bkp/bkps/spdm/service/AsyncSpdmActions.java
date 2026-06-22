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

package com.intel.bkp.bkps.spdm.service;

import com.intel.bkp.bkps.attestation.AttestationParams;
import com.intel.bkp.bkps.attestation.SpdmDiceAttestationService;
import com.intel.bkp.bkps.domain.AesKey;
import com.intel.bkp.bkps.domain.ConfidentialData;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.exception.ExceededOvebuildException;
import com.intel.bkp.bkps.exception.InvalidConfigurationException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.protocol.common.MessagesForSigmaEncPayload;
import com.intel.bkp.bkps.protocol.common.model.RootChainType;
import com.intel.bkp.bkps.protocol.common.service.BkpsDHCertBuilder;
import com.intel.bkp.bkps.rest.provisioning.service.IServiceConfiguration;
import com.intel.bkp.bkps.rest.provisioning.service.OverbuildCounterManager;
import com.intel.bkp.bkps.rest.provisioning.service.ProvisioningHistoryService;
import com.intel.bkp.bkps.spdm.jna.SpdmParametersProviderImpl;
import com.intel.bkp.bkps.spdm.model.SpdmThreadError;
import com.intel.bkp.bkps.utils.MdcHelper;
import com.intel.bkp.command.logger.CommandLogger;
import com.intel.bkp.command.messages.common.VolatileAesErase;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.command.responses.common.CertificateResponse;
import com.intel.bkp.command.responses.common.CertificateResponseBuilder;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import com.intel.bkp.fpgacerts.exceptions.SpdmAttestationException;
import com.intel.bkp.protocol.spdm.exceptions.SpdmCommandFailedException;
import com.intel.bkp.protocol.spdm.exceptions.SpdmNotSupportedException;
import com.intel.bkp.protocol.spdm.exceptions.UnsupportedCapabilityException;
import com.intel.bkp.protocol.spdm.exceptions.UnsupportedSpdmVersionException;
import com.intel.bkp.protocol.spdm.exceptions.ValidChainNotFoundException;
import com.intel.bkp.protocol.spdm.jna.model.MctpEncapsulationTypeCallback;
import com.intel.bkp.protocol.spdm.jna.model.SpdmParametersProvider;
import com.intel.bkp.protocol.spdm.jna.model.SpdmProtocol;
import com.intel.bkp.protocol.spdm.jna.model.Uint8;
import com.intel.bkp.protocol.spdm.service.SpdmGetCertificateMessageSender;
import com.intel.bkp.protocol.spdm.service.SpdmGetVersionMessageSender;
import com.intel.bkp.protocol.spdm.service.SpdmSecureSessionMessageSender;
import com.intel.bkp.protocol.spdm.service.SpdmSetAuthorityMessageSender;
import com.intel.bkp.protocol.spdm.service.SpdmVcaMessageSender;
import com.intel.bkp.protocol.spdm.service.SpdmVersionVerifier;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

import static com.intel.bkp.command.logger.CommandLoggerValues.CERTIFICATE_RESPONSE;
import static com.intel.bkp.command.logger.CommandLoggerValues.VOLATILE_AES_ERASE_MESSAGE;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmCapabilities.SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
import static com.intel.bkp.utils.HexConverter.toFormattedHex;
import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
@Component
@RequiredArgsConstructor
public class AsyncSpdmActions {

    private static final String SPDM_SUPPORTED_VERSION = "12";
    private static final Uint8 MCTP_ENCAPSULATION_FOR_SECURE_SESSION = new Uint8(0);

    private final SpdmVersionVerifier spdmVersionVerifier = new SpdmVersionVerifier(SPDM_SUPPORTED_VERSION);
    private final SpdmParametersProvider spdmParametersProvider = new SpdmParametersProviderImpl();
    private final SpdmErrorProcessResultHolder processResult = new SpdmErrorProcessResultHolder();

    @Value("${lib-spdm-params.wrapper-library-path}")
    private String wrapperLibraryPath;

    private final BkpsDHCertBuilder bkpsDHCertBuilder;
    private final FinishMessageSigner finishMessageSigner;
    private final MessagesForSigmaEncPayload messagesForSigmaEncPayload;
    private final ProvisioningHistoryService provisioningHistoryService;
    private final OverbuildCounterManager overbuildCounterManager;
    private final CommandLayer commandLayer;
    private final SpdmDiceAttestationService attestationService;
    private final SpdmMessageSenderService spdmMessageSenderService;

    @Getter
    private boolean processing = false;

    private SpdmProtocol12Impl initializeLibrary() {
        return new SpdmProtocol12Impl(wrapperLibraryPath, () -> bkpsDHCertBuilder.getChain(RootChainType.MULTI),
            spdmMessageSenderService, spdmParametersProvider, finishMessageSigner);
    }

    public boolean isProcessResult() {
        return processResult.ready();
    }

    public Optional<SpdmThreadError> getProcessResult() {
        return Optional.ofNullable(processResult.consume());
    }

    @Async("spdmTaskExecutor")
    public void getVersionThread(String mainThreadTxId) {
        MdcHelper.add(mainThreadTxId);

        try (final SpdmProtocol spdmProtocol = initializeLibrary()) {
            processing = true;

            final String responderVersion = new SpdmGetVersionMessageSender(spdmProtocol).send();
            log.debug("SPDM Responder version: {}", responderVersion);

            spdmVersionVerifier.ensureVersionIsSupported(responderVersion);
            processResult.success();
        } catch (SpdmNotSupportedException e) {
            log.debug("SPDM not supported: ", e);
            processResult.failure();
        } catch (UnsupportedSpdmVersionException e) {
            log.debug("Unsupported SPDM version: ", e);
            processResult.failure();
        } catch (Exception e) {
            log.debug("Processing failed.", e);
            processResult.failure();
        } finally {
            processing = false;
        }
    }

    @Async("spdmTaskExecutor")
    public void setAuthorityThread(String mainThreadTxId, List<byte[]> certificateChain, int slotId, Boolean isMctpEncapsulateSupported) {
        MdcHelper.add(mainThreadTxId);

        try (final SpdmProtocol spdmProtocol = initializeLibrary()) {
            processing = true;

            if (isMctpEncapsulateSupported) {
                initializeConnectionAndEnsureVersionSupported(spdmProtocol,
                    () -> MCTP_ENCAPSULATION_FOR_SECURE_SESSION);
                log.info("SPDM Responder initialized for Set Authority.");
                // For SDM 1.5 and above, we need to setup secure session to overwrite the slots if the certificate chain is present
                SpdmSecureSessionMessageSender spdmSecureSessionMessageSender = null;
                Boolean needSecureSession = false;
                try {
                    log.info("Requesting chain from slot {}.", slotId);
                    SpdmGetCertificateMessageSender spdmGetCertificateMessageSender = new SpdmGetCertificateMessageSender(spdmProtocol);
                    final var certChain = Optional.ofNullable(spdmGetCertificateMessageSender.send(slotId))
                        .filter(value -> value.length != 0)
                        .orElse(null);

                    log.info("Certificate chain {} in slot {}.", (certChain == null) ? "not found" : "found", slotId);

                    needSecureSession = (certChain != null);
                } catch (Exception e) {
                    log.info("Skipping secure session set up.");
                }

                if (needSecureSession) {
                    log.info("Setting up secure session.");
                    spdmSecureSessionMessageSender = new SpdmSecureSessionMessageSender(spdmProtocol);
                    spdmSecureSessionMessageSender.startSession(slotId, false);
                } else {
                    log.info("Secure session is not required.");
                }

                new SpdmSetAuthorityMessageSender(spdmProtocol).send(certificateChain, slotId);

                if (needSecureSession && spdmSecureSessionMessageSender != null) {
                    spdmSecureSessionMessageSender.endSession();
                }

            } else {
                initializeConnectionAndEnsureVersionSupported(spdmProtocol);
                log.info("SPDM Responder initialized for Set Authority.");
                new SpdmSetAuthorityMessageSender(spdmProtocol).send(certificateChain, slotId);
            }

            processResult.success();
        } catch (SpdmNotSupportedException e) {
            log.debug("SPDM not supported: ", e);
            processResult.failure();
        } catch (UnsupportedSpdmVersionException e) {
            log.debug("Unsupported SPDM version: ", e);
            processResult.failure();
        } catch (Exception e) {
            log.debug("Processing failed.", e);
            processResult.failure();
        } finally {
            processing = false;
        }
    }

    @Async("spdmTaskExecutor")
    public void vcaForSecureSessionThread(String mainThreadTxId) {
        MdcHelper.add(mainThreadTxId);

        try (final SpdmProtocol spdmProtocol = initializeLibrary()) {
            processing = true;

            initializeConnectionAndEnsureVersionSupported(spdmProtocol);
            checkCapability(spdmProtocol, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP, "KEY_EX_CAP");
            processResult.success();
        } catch (SpdmNotSupportedException e) {
            log.debug("SPDM not supported: ", e);
            processResult.failure();
        } catch (UnsupportedSpdmVersionException e) {
            log.debug("Unsupported SPDM version: ", e);
            processResult.failure();
        } catch (UnsupportedCapabilityException e) {
            log.debug("SPDM capability not supported: ", e);
            processResult.unsupportedCap();
        } catch (Exception e) {
            log.debug("Processing failed.", e);
            processResult.failure();
        } finally {
            processing = false;
        }
    }

    @Async("spdmTaskExecutor")
    public void secureSessionThread(String mainThreadTxId, String uid, long cfgId,
                                    IServiceConfiguration configurationCallback) {
        MdcHelper.add(mainThreadTxId);

        try (final SpdmProtocol spdmProtocol = initializeLibrary()) {
            processing = true;

            initializeConnectionAndEnsureVersionSupported(spdmProtocol, () -> MCTP_ENCAPSULATION_FOR_SECURE_SESSION);
            log.info("SPDM Responder initialized for Secure Session.");

            log.info("Fetch configuration data for cfg id: " + cfgId);
            final ServiceConfiguration configuration = configurationCallback.getConfiguration(cfgId);

            final var attestationParams = AttestationParams.from(configuration);
            final var slotId = attestationService.performAttestationAndGetSlotId(spdmProtocol, uid, attestationParams);

            final var spdmSecureSessionMessageSender = new SpdmSecureSessionMessageSender(spdmProtocol);
            spdmSecureSessionMessageSender.startSession(slotId, true);

            if (isClearBbramApplicable(cfgId, configuration)) {
                log.debug("Sending VOLATILE_AES_ERASE ... ");
                final VolatileAesErase volatileAesErase = new VolatileAesErase();
                final byte[] payload = commandLayer.create(volatileAesErase, CommandIdentifier.VOLATILE_AES_ERASE);
                CommandLogger.log(volatileAesErase, VOLATILE_AES_ERASE_MESSAGE, this.getClass());
                final byte[] volatileAesEraseResponse = commandLayer.retrieve(
                    spdmSecureSessionMessageSender.sendData(payload), CommandIdentifier.VOLATILE_AES_ERASE);

                if (volatileAesEraseResponse.length > 0) {
                    throw new ProvisioningGenericException(
                        "VOLATILE_AES_ERASE (clear BBRAM) response is invalid.\nIt should be empty, but is: %s"
                            .formatted(toHex(volatileAesEraseResponse)));
                }
            }

            final byte[] certificateToBeProvisioned = messagesForSigmaEncPayload.prepareFrom(configuration);
            incrementOverbuildCounter(configurationCallback, uid, cfgId, configuration.getPufType());

            log.debug("Sending CERTIFICATE with User AES Root Key Certificate ... ");
            final byte[] provisioningResponse = spdmSecureSessionMessageSender.sendData(certificateToBeProvisioned);
            final CertificateResponse certificateResponse = buildCertificateResponse(provisioningResponse);
            verifyProcessCompleted(certificateResponse);

            spdmSecureSessionMessageSender.endSession();

            processResult.success();
        } catch (ValidChainNotFoundException e) {
            log.error("Valid chain not found.", e);
            processResult.attestationFailed();
        } catch (SpdmAttestationException e) {
            log.error("Attestation failed.", e);
            processResult.attestationFailed();
        } catch (UnsupportedSpdmVersionException e) {
            log.debug("Unsupported SPDM version: ", e);
            processResult.failure();
        } catch (Exception e) {
            log.debug("Processing failed.", e);
            processResult.failure();
        } finally {
            processing = false;
        }
    }

    private boolean isClearBbramApplicable(Long cfgId, ServiceConfiguration configuration) {
        return StorageType.BBRAM.equals(getStorageType(cfgId, configuration));
    }

    private StorageType getStorageType(Long cfgId, ServiceConfiguration configuration) {
        return Optional.ofNullable(configuration)
            .map(ServiceConfiguration::getConfidentialData)
            .map(ConfidentialData::getAesKey)
            .map(AesKey::getStorage)
            .orElseThrow(() -> new InvalidConfigurationException(cfgId));
    }

    private void initializeConnectionAndEnsureVersionSupported(
        SpdmProtocol spdmProtocol) throws SpdmCommandFailedException, UnsupportedSpdmVersionException {
        final String responderVersion = new SpdmVcaMessageSender(spdmProtocol).send();

        spdmVersionVerifier.ensureVersionIsSupported(responderVersion);
    }

    private void initializeConnectionAndEnsureVersionSupported(SpdmProtocol spdmProtocol,
                                                               MctpEncapsulationTypeCallback callback)
        throws SpdmCommandFailedException, UnsupportedSpdmVersionException {
        final String responderVersion = new SpdmVcaMessageSender(spdmProtocol).send(callback);

        spdmVersionVerifier.ensureVersionIsSupported(responderVersion);
    }

    private static void checkCapability(SpdmProtocol spdmProtocol, int capability,
                                        String capabilityFriendlyName) throws UnsupportedCapabilityException {

        final String capabilityMsg = "%s = %s".formatted(capabilityFriendlyName, toFormattedHex(capability));
        log.info("Checking if capability is supported: {}", capabilityMsg);

        final boolean supported = spdmProtocol.checkSpdmResponderCapability(capability);

        if (!supported) {
            log.debug("Capability is not supported: {}", capabilityMsg);
            throw new UnsupportedCapabilityException(capabilityMsg);
        }

        log.debug("Capability is supported: {}", capabilityMsg);
    }

    private CertificateResponse buildCertificateResponse(byte[] decryptedPayloadValue) {
        final CertificateResponseBuilder certificateResponseBuilder = new CertificateResponseBuilder();
        final CertificateResponse certificateResponse = certificateResponseBuilder
            .withActor(EndiannessActor.FIRMWARE)
            .parse(commandLayer.retrieve(decryptedPayloadValue, CommandIdentifier.CERTIFICATE))
            .withActor(EndiannessActor.SERVICE)
            .build();

        CommandLogger.log(certificateResponseBuilder.withActor(EndiannessActor.FIRMWARE).build(),
            CERTIFICATE_RESPONSE, this.getClass());
        return certificateResponse;
    }

    private void verifyProcessCompleted(CertificateResponse certificateResponse) {
        if (certificateResponse.processCompleted()) {
            log.info("Certificate provisioning process completed.");
        } else {
            throw new ProvisioningGenericException(
                String.format("Certificate provisioning process error: %s",
                    toHex(certificateResponse.getCertificateProcessStatus())));
        }
    }

    private void incrementOverbuildCounter(IServiceConfiguration configurationCallback, String uid, long cfgId,
                                           PufType pufType) {
        log.info("Setting device as provisioned ...");
        if (markDeviceProvisioned(uid, pufType)) {
            try {
                overbuildCounterManager.increment(configurationCallback, cfgId);
            } catch (ExceededOvebuildException e) {
                throw new ProvisioningGenericException("Failed to increment overbuild counter: ", e);
            }
        }
    }

    private boolean markDeviceProvisioned(String deviceIdHex, PufType pufType) {
        return provisioningHistoryService.getCurrentProvisionedStatusAndUpdate(deviceIdHex, pufType);
    }

    static class ProcessResultHolder<T> {

        private T processResult;

        synchronized boolean ready() {
            return processResult != null;
        }

        synchronized void produce(T item) {
            processResult = item;
        }

        synchronized T consume() {
            T result = processResult;
            processResult = null;
            return result;
        }
    }

    static class SpdmErrorProcessResultHolder extends ProcessResultHolder<SpdmThreadError> {

        synchronized void success() {
            produce(SpdmThreadError.SUCCESS);
        }

        synchronized void failure() {
            produce(SpdmThreadError.FAILURE);
        }

        synchronized void attestationFailed() {
            produce(SpdmThreadError.ATTESTATION_FAILED);
        }

        synchronized void unsupportedCap() {
            produce(SpdmThreadError.UNSUPPORTED_CAP);
        }
    }
}
