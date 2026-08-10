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

package com.intel.bkp.protocol.spdm.jna;

import com.intel.bkp.protocol.spdm.exceptions.SpdmCommandFailedException;
import com.intel.bkp.protocol.spdm.exceptions.SpdmConnectionNotInitialized;
import com.intel.bkp.protocol.spdm.exceptions.SpdmRuntimeException;
import com.intel.bkp.protocol.spdm.exceptions.SpdmSecureSessionNotInitialized;
import com.intel.bkp.protocol.spdm.jna.model.CustomMemory;
import com.intel.bkp.protocol.spdm.jna.model.LibSpdmLibraryWrapper;
import com.intel.bkp.protocol.spdm.jna.model.LibSpdmReturn;
import com.intel.bkp.protocol.spdm.jna.model.MctpEncapsulationTypeCallback;
import com.intel.bkp.protocol.spdm.jna.model.MessageSender;
import com.intel.bkp.protocol.spdm.jna.model.NativeSize;
import com.intel.bkp.protocol.spdm.jna.model.SessionCallbacks;
import com.intel.bkp.protocol.spdm.jna.model.SpdmContext;
import com.intel.bkp.protocol.spdm.jna.model.SpdmGetDigestResult;
import com.intel.bkp.protocol.spdm.jna.model.SpdmParametersProvider;
import com.intel.bkp.protocol.spdm.jna.model.SpdmProtocol;
import com.intel.bkp.protocol.spdm.jna.model.Uint16;
import com.intel.bkp.protocol.spdm.jna.model.Uint32;
import com.intel.bkp.protocol.spdm.jna.model.Uint64;
import com.intel.bkp.protocol.spdm.jna.model.Uint8;
import com.intel.bkp.protocol.spdm.service.SpdmSetCertificateBuilder;
import com.intel.bkp.utils.ByteBufferSafe;
import com.sun.jna.Memory;
import com.sun.jna.ptr.ByteByReference;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

import static com.intel.bkp.protocol.spdm.jna.SpdmUtils.getBytes;
import static com.intel.bkp.protocol.spdm.jna.SpdmUtils.throwOnError;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmReturn.LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmReturn.LIBSPDM_STATUS_SUCCESS;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.MAX_LOCAL_CERTIFICATE_CHAIN_SIZE;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.MAX_SPDM_BUFFER_SIZE;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_KEY_EXCHANGE_REQUEST_ALL_MEASUREMENTS_HASH;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH;
import static com.intel.bkp.utils.BitUtils.countSetBits;
import static com.intel.bkp.utils.HexConverter.toFormattedHex;
import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
public abstract class SpdmProtocol12 implements SpdmProtocol {

    private static final int SHA384_LEN = 48;

    private final SpdmParametersSetter spdmParametersSetter = new SpdmParametersSetter();
    @Getter
    private final SessionCallbacks callbacks = new SessionCallbacks();
    private final SpdmCallbacks spdmCallbacks;
    private final SpdmParametersProvider parametersProvider;

    private SpdmContext spdmContext;
    private final Memory certificateChain = new CustomMemory(MAX_LOCAL_CERTIFICATE_CHAIN_SIZE);

    private int secureSessionId = 0;

    private final Memory sessionId = new CustomMemory(Uint32.SIZE);

    @Getter
    private boolean connectionInitialized = false;

    @Getter
    private boolean secureSessionInitialized = false;

    private String expectedMeasurementHash;

    protected LibSpdmLibraryWrapper jnaInterface;

    protected abstract void initializeLibrary();

    protected byte[] getCertChain() {
        return new byte[0];
    }

    protected SpdmProtocol12(MessageSender messageSender,
                             SpdmParametersProvider parametersProvider,
                             SignatureProvider signatureProvider) {
        this.spdmCallbacks = new SpdmCallbacks(messageSender, signatureProvider);
        this.parametersProvider = parametersProvider;
    }

    protected SpdmProtocol12(MessageSender messageSender,
                             SpdmParametersProvider parametersProvider) {
        this.spdmCallbacks = new SpdmCallbacks(messageSender);
        this.parametersProvider = parametersProvider;
    }

    @Override
    public String getVersion() throws SpdmCommandFailedException {
        initializeLibrary();
        initializeSpdmContext();
        return getVersionInternal();
    }

    @Override
    public void initSpdmConnection() throws SpdmCommandFailedException {
        initializeLibrary();
        initializeSpdmContext();
        initializeConnection();
    }

    @Override
    public void initSpdmConnection(MctpEncapsulationTypeCallback callback) throws SpdmCommandFailedException {
        initializeLibrary();
        initializeSpdmContext(callback);
        initializeConnection();
    }

    @Override
    public String retrieveSpdmVersion() {
        if (!isConnectionInitialized()) {
            throw new SpdmConnectionNotInitialized();
        }

        final ByteBuffer buffer = ByteBuffer.allocate(Byte.BYTES);
        jnaInterface.libspdm_get_version_w(spdmContext.getContext(), buffer);

        return toHex(buffer.get());
    }

    @Override
    public boolean checkSpdmResponderCapability(int capability) {
        if (!isConnectionInitialized()) {
            throw new SpdmConnectionNotInitialized();
        }

        return jnaInterface.libspdm_is_capabilities_flag_supported_by_responder(
            spdmContext.getContext(), new Uint32(capability));
    }

    @Override
    public SpdmGetDigestResult getDigest() throws SpdmCommandFailedException {
        if (!isConnectionInitialized()) {
            throw new SpdmConnectionNotInitialized();
        }

        return getDigestInternal();
    }

    @Override
    public String getCerts(int slotId) throws SpdmCommandFailedException {
        if (!isConnectionInitialized()) {
            throw new SpdmConnectionNotInitialized();
        }

        return getCertsInternal(slotId);
    }

    @Override
    public String getMeasurements(int slotId) throws SpdmCommandFailedException {
        if (!isConnectionInitialized()) {
            throw new SpdmConnectionNotInitialized();
        }

        return getMeasurementsInternal(slotId);
    }

    @Override
    public void setAuthority(List<byte[]> certificateChain, int slotId) throws SpdmCommandFailedException {
        if (!isConnectionInitialized()) {
            throw new SpdmConnectionNotInitialized();
        }

        setAuthorityInternal(certificateChain, slotId);
    }

    @Override
    public void startSecureSession(int measurementSlotId, Boolean needMeasurementHash) throws SpdmCommandFailedException {
        if (!isConnectionInitialized()) {
            throw new SpdmConnectionNotInitialized();
        }

        final int sessionId = startSecureSessionInternal(measurementSlotId, needMeasurementHash);

        if (sessionId == 0) {
            throw new SpdmRuntimeException("Secure session not initialized.");
        }

        log.debug("Secure session initialized.");
        secureSessionId = sessionId;
        secureSessionInitialized = true;
    }

    @Override
    public void stopSecureSession() throws SpdmCommandFailedException {
        if (!isConnectionInitialized()) {
            throw new SpdmConnectionNotInitialized();
        }

        if (!isSecureSessionInitialized()) {
            throw new SpdmSecureSessionNotInitialized();
        }

        stopSecureSessionInternal();
        sessionId.clear(Uint32.SIZE);
        secureSessionId = 0;
        secureSessionInitialized = false;
    }

    @Override
    public byte[] sendReceiveDataInSession(byte[] payload) throws SpdmCommandFailedException {
        if (!isConnectionInitialized()) {
            throw new SpdmConnectionNotInitialized();
        }

        if (!isSecureSessionInitialized()) {
            throw new SpdmSecureSessionNotInitialized();
        }

        return sendDataInSecureSessionInternal(payload);
    }

    @Override
    public void deinitialize() {
        if (spdmContext != null) {
            jnaInterface.libspdm_deinit_context_w(spdmContext.getContext());
        }
    }

    private void registerCallbacks(long spdmContextSize, MctpEncapsulationTypeCallback mctpEncapsulationTypeCallback) {
        spdmCallbacks.setSpdmContextSize(spdmContextSize);
        callbacks.setPrintCallback(spdmCallbacks::printCallback);
        callbacks.setSpdmDeviceSendMessageCallback(spdmCallbacks::spdmDeviceSendMessage);
        callbacks.setSpdmDeviceReceiveMessageCallback(spdmCallbacks::spdmDeviceReceiveMessage);
        callbacks.setSpdmRequesterDataSignCallback(spdmCallbacks::spdmRequesterDataSignCallback);
        callbacks.setMctpEncapsulationTypeCallback(mctpEncapsulationTypeCallback);
    }

    private void initializeSpdmContext() {
        initializeSpdmContext(null);
    }

    private void initializeSpdmContext(MctpEncapsulationTypeCallback mctpEncapsulationTypeCallback) {
        if (spdmContext != null) {
            log.debug("SPDM context already initialized.");
            return;
        }

        log.debug("Initializing SPDM context.");

        final long spdmContextSize = jnaInterface.libspdm_get_context_size_w().longValue();
        registerCallbacks(spdmContextSize, mctpEncapsulationTypeCallback);
        jnaInterface.set_callbacks(callbacks);

        spdmContext = new SpdmContext(spdmContextSize);

        final LibSpdmReturn status = jnaInterface.libspdm_prepare_context_w(spdmContext.getContext(),
            new Uint32(LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE));

        log.debug("Initialize context status: {}", toFormattedHex(status.asLong()));

        if (!LIBSPDM_STATUS_SUCCESS.equals(status)) {
            throw new SpdmRuntimeException("Failed to initialize SPDM context.");
        }

        final NativeSize scratchBufferSize =
            jnaInterface.libspdm_get_sizeof_required_scratch_buffer_w(spdmContext.getContext());
        spdmContext.withScratchBuffer(scratchBufferSize);

        jnaInterface.libspdm_set_scratch_buffer_w(spdmContext.getContext(), spdmContext.getScratchBuffer(),
            new NativeSize(spdmContext.getScratchBufferSize()));

        spdmParametersSetter
            .with(jnaInterface, spdmContext.getContext())
            .setLibspdmParameters(parametersProvider)
            .setCertChain(0, getCertChain(), certificateChain);

    }

    private void initializeConnection() throws SpdmCommandFailedException {
        if (!isConnectionInitialized()) {
            log.debug("Initializing SPDM connection.");
            initSpdmConnectionInternal();
            connectionInitialized = true;
        }
    }

    private String getVersionInternal() throws SpdmCommandFailedException {
        log.debug("Sending SPDM GET_VERSION ...");

        final LibSpdmReturn status = jnaInterface.libspdm_init_connection_w(spdmContext.getContext(), true);
        log.debug("VERSION status: {}", toFormattedHex(status.asLong()));

        throwOnError(status);

        final ByteBuffer buffer = ByteBuffer.allocate(Byte.BYTES);
        jnaInterface.libspdm_get_version_w(spdmContext.getContext(), buffer);

        return toHex(buffer.get());
    }

    private void initSpdmConnectionInternal() throws SpdmCommandFailedException {
        log.debug("Sending SPDM GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHMS (VCA) ...");

        final LibSpdmReturn status = jnaInterface.libspdm_init_connection_w(spdmContext.getContext(), false);
        log.debug("Init connection status: {}", toFormattedHex(status.asLong()));

        throwOnError(status);
    }

    private SpdmGetDigestResult getDigestInternal() throws SpdmCommandFailedException {
        log.debug("Sending SPDM GET_DIGESTS ...");

        try (final Memory digestBuffer = new CustomMemory(MAX_SPDM_BUFFER_SIZE)) {
            final ByteByReference slotMask = new ByteByReference();
            final LibSpdmReturn status = jnaInterface.libspdm_get_digest_w(spdmContext.getContext(), null,
                slotMask, digestBuffer);
            log.debug("DIGESTS status: {}", toFormattedHex(status.asLong()));

            throwOnError(status);

            final int hashAlgSize = SHA384_LEN;
            final byte slotMaskValue = slotMask.getValue();
            return new SpdmGetDigestResult(slotMaskValue,
                getBytes(digestBuffer, countSetBits(slotMaskValue) * hashAlgSize), hashAlgSize);
        }

    }

    private String getCertsInternal(int slotId) throws SpdmCommandFailedException {
        log.debug("Sending SPDM GET_CERTIFICATE ...");

        try (final Memory certChain = new CustomMemory(MAX_SPDM_BUFFER_SIZE);
             final Memory certChainSize = new CustomMemory(Long.BYTES)) {
            certChainSize.setLong(0, MAX_SPDM_BUFFER_SIZE);

            final LibSpdmReturn status = jnaInterface.libspdm_get_certificate_w(spdmContext.getContext(),
                null, new Uint8(slotId), certChainSize, certChain);
            log.debug("CERTIFICATE status: {}", toFormattedHex(status.asLong()));

            throwOnError(status);

            final byte[] certChainArray = getBytes(certChain, certChainSize);

            final String chain = toHex(certChainArray);
            log.debug("CERTIFICATE: {}", chain);

            return chain;
        }
    }

    private String getMeasurementsInternal(int slotId) throws SpdmCommandFailedException {
        log.debug("Sending SPDM GET_MEASUREMENTS ...");

        try (final Memory measurementRecord = new CustomMemory(MAX_SPDM_BUFFER_SIZE);
             final Memory measurementRecordLength = new CustomMemory(Integer.BYTES);
             final Memory numberOfBlocks = new CustomMemory(Uint8.SIZE)) {

            measurementRecordLength.setInt(0, MAX_SPDM_BUFFER_SIZE);

            final LibSpdmReturn status = jnaInterface.libspdm_get_measurement_w(spdmContext.getContext(), null,
                getRequestAttributes(), new Uint8(SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS),
                new Uint8(slotId), null, numberOfBlocks,
                measurementRecordLength, measurementRecord);
            log.debug("MEASUREMENTS status: {}", toFormattedHex(status.asLong()));

            throwOnError(status);

            final byte[] measurementsArray = getBytes(measurementRecord, measurementRecordLength);
            final byte[] numberOfBlocksArray = getBytes(numberOfBlocks, Uint8.SIZE);

            final String measurements = toHex(measurementsArray);
            expectedMeasurementHash = toHex(DigestUtils.sha384(measurementsArray));
            final int numberOfBlocksInt = ByteBufferSafe.wrap(numberOfBlocksArray).getByte();
            log.debug("MEASUREMENTS (blocks: {}): {}", numberOfBlocksInt, measurements);

            return measurements;
        }
    }

    private void setAuthorityInternal(List<byte[]> certificateChain, int slotId) throws SpdmCommandFailedException {
        log.debug("Sending SPDM SET_CERTIFICATE ...");
        final var setCertificateBuilder = new SpdmSetCertificateBuilder().parse(certificateChain);
        final byte[] certChainBufferArray = setCertificateBuilder.build();
        final int certChainLen = certChainBufferArray.length;

        try (final Memory certChain = new CustomMemory(certChainLen)) {
            certChain.write(0, certChainBufferArray, 0, certChainLen);

            final LibSpdmReturn setCertStatus = jnaInterface.libspdm_set_certificate_w(spdmContext.getContext(), null,
                new Uint8(slotId), certChain, new NativeSize(setCertificateBuilder.getLenOfCertChain()));
            log.debug("Set certificate status: {}", toFormattedHex(setCertStatus.asLong()));

            throwOnError(setCertStatus);
        }
    }

    private int startSecureSessionInternal(int measurementSlotId, Boolean needMeasurementHash) throws SpdmCommandFailedException {
        log.debug("Sending SPDM KEY_EXCHANGE ...");

        try (final Memory heartbeatPeriod = new CustomMemory(Uint8.SIZE);
             final Memory measurementHash = new CustomMemory(SHA384_LEN)) {
            sessionId.clear(Uint32.SIZE);
            heartbeatPeriod.clear(Uint8.SIZE);
            measurementHash.clear(SHA384_LEN);
            int keyExchangeReq = needMeasurementHash ? SPDM_KEY_EXCHANGE_REQUEST_ALL_MEASUREMENTS_HASH : SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH;
            final LibSpdmReturn status = jnaInterface.libspdm_start_session_w(spdmContext.getContext(), false, null,
                new Uint16(0), new Uint8(keyExchangeReq),
                new Uint8(measurementSlotId), new Uint8(0), sessionId, heartbeatPeriod, measurementHash);

            log.debug("KEY_EXCHANGE status: {}", toFormattedHex(status.asLong()));
            final byte[] sessionIdBytes = getBytes(sessionId, Uint32.SIZE);
            if (needMeasurementHash) {
                final byte[] measurementHashBytes = getBytes(measurementHash, SHA384_LEN);
                if (!expectedMeasurementHash.isEmpty()) {
                    if (!toHex(measurementHashBytes).equals(expectedMeasurementHash)) {
                        log.error("Measurement hash mismatch.");
                        throwOnError(LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION);
                    }
                } else {
                    log.error("Expected measurement hash is empty.");
                    throwOnError(LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION);
                }
            }

            throwOnError(status);

            return ByteBufferSafe.wrap(sessionIdBytes).getInt(ByteOrder.LITTLE_ENDIAN);
        }
    }

    private byte[] sendDataInSecureSessionInternal(byte[] payload) throws SpdmCommandFailedException {
        log.debug("Sending VENDOR_DEFINED_REQUEST in session ...");
        final int payloadLen = payload.length;
        final int responseBufferLen = MAX_SPDM_BUFFER_SIZE;

        try (final Memory payloadP = new CustomMemory(payloadLen);
             final Memory responseP = new CustomMemory(responseBufferLen);
             final Memory responseSizeP = new CustomMemory(Uint64.SIZE)) {
            payloadP.clear(payloadLen);
            responseP.clear(responseBufferLen);
            responseSizeP.clear(Uint64.SIZE);

            responseSizeP.setLong(0, responseBufferLen);
            for (int i = 0; i < payloadLen; i++) {
                payloadP.setByte(i, payload[i]);
            }

            final LibSpdmReturn status = jnaInterface.libspdm_send_receive_data_w(spdmContext.getContext(),
                sessionId, false, payloadP, new NativeSize(payloadLen), responseP, responseSizeP);

            log.debug("VENDOR_DEFINED_REQUEST status: {}", toFormattedHex(status.asLong()));

            throwOnError(status);

            return getBytes(responseP, responseSizeP);
        }
    }

    private void stopSecureSessionInternal() throws SpdmCommandFailedException {
        log.debug("Sending SPDM END_SESSION ...");

        final LibSpdmReturn status = jnaInterface.libspdm_stop_session_w(spdmContext.getContext(),
            new Uint32(secureSessionId), new Uint8(0));

        log.debug("END_SESSION status: {}", toFormattedHex(status.asLong()));

        throwOnError(status);
    }

    private Uint8 getRequestAttributes() {
        if (isMeasurementsRequestSignature()) {
            log.info("Verifying signature over measurements.");
            return new Uint8(SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE);
        } else {
            log.info("Skipping signature verification over measurements.");
            return new Uint8(0);
        }
    }

    @Override
    public void close() throws Exception {
        deinitialize();

        if (spdmContext != null) {
            spdmContext.close();
            spdmContext = null;
        }

        certificateChain.close();
        sessionId.close();
    }
}
