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

package com.intel.bkp.protocol.spdm.jna.model;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.ByteByReference;

import java.nio.ByteBuffer;

public interface LibSpdmLibraryWrapper extends Library {

    static LibSpdmLibraryWrapper getInstance(String wrapperLibraryPath) {
        return Native.load(wrapperLibraryPath, LibSpdmLibraryWrapper.class);
    }

    void set_callbacks(SessionCallbacks callbacks);

    void libspdm_get_version_w(Pointer spdmContext, ByteBuffer version);

    NativeSize libspdm_get_context_size_w();

    void libspdm_deinit_context_w(Pointer spdmContext);

    boolean libspdm_is_capabilities_flag_supported_by_responder(Pointer spdmContext,
                                                                Uint32 responderCapabilitiesFlag);

    LibSpdmReturn libspdm_prepare_context_w(Pointer spdmContextP, Uint32 bufferSize);

    NativeSize libspdm_get_sizeof_required_scratch_buffer_w(Pointer spdmContextP);

    void libspdm_set_scratch_buffer_w(Pointer spdmContextP, Pointer scratchBuffer, NativeSize scratchBufferSize);

    LibSpdmReturn libspdm_init_connection_w(Pointer spdmContextP, boolean versionOnly);

    LibSpdmReturn libspdm_set_data_w(Pointer spdmContext, int dataType,
                                     LibSpdmDataParameter parameter,
                                     Pointer data, NativeSize dataSize);

    LibSpdmReturn libspdm_get_digest_w(Pointer spdmContext, Pointer sessionId, ByteByReference slotMask,
                                       Pointer totalDigestBuffer);

    LibSpdmReturn libspdm_get_certificate_w(Pointer spdmContext, Pointer sessionId,
                                            Uint8 slotId, Pointer certChainSize, Pointer certChain);

    LibSpdmReturn libspdm_get_measurement_w(Pointer spdmContext, Pointer sessionId,
                                            Uint8 requestAttribute, Uint8 measurementOperation, Uint8 slotId,
                                            Pointer contentChanged, Pointer numberOfBlocks,
                                            Pointer measurementRecordLength, Pointer measurementRecord);

    LibSpdmReturn libspdm_set_certificate_w(Pointer spdmContext, Pointer sessionId, Uint8 slotId,
                                            Pointer certChain, NativeSize certChainSize);

    LibSpdmReturn libspdm_start_session_w(Pointer spdmContext, boolean usePsk, Pointer pskHint, Uint16 pskHintSize,
                                          Uint8 measurementHashType, Uint8 slotId, Uint8 sessionPolicy,
                                          Pointer sessionId,
                                          Pointer heartbeatPeriod, Pointer measurementHash);

    LibSpdmReturn libspdm_stop_session_w(Pointer spdmContext, Uint32 sessionId, Uint8 endSessionAttributes);

    LibSpdmReturn libspdm_send_receive_data_w(Pointer spdmContext, Pointer sessionId, boolean isAppMessage,
                                              Pointer request, NativeSize requestSize, Pointer response,
                                              Pointer responseSize);

}
