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

package com.intel.bkp.bkps.spdm.service;

import com.intel.bkp.bkps.spdm.jna.LibSpdmLibraryWrapperImpl;
import com.intel.bkp.core.exceptions.BKPInternalRuntimeException;
import com.intel.bkp.protocol.spdm.jna.SignatureProvider;
import com.intel.bkp.protocol.spdm.jna.SpdmProtocol12;
import com.intel.bkp.protocol.spdm.jna.model.MessageSender;
import com.intel.bkp.protocol.spdm.jna.model.SpdmParametersProvider;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Getter(AccessLevel.PACKAGE)
public class SpdmProtocol12Impl extends SpdmProtocol12 {

    private final QkyChainProvider qkyChainProvider;
    private final String wrapperLibraryPath;

    public SpdmProtocol12Impl(String wrapperLibraryPath, QkyChainProvider qkyChainProvider,
                              MessageSender messageSender, SpdmParametersProvider parametersProvider,
                              SignatureProvider signatureProvider) {
        super(messageSender, parametersProvider, signatureProvider);
        this.qkyChainProvider = qkyChainProvider;
        this.wrapperLibraryPath = wrapperLibraryPath;
    }

    @Override
    protected void initializeLibrary() {
        if (jnaInterface != null) {
            log.debug("SPDM Wrapper library already initialized.");
            return;
        }

        log.debug("Loading SPDM Wrapper library.");

        try {
            jnaInterface = new LibSpdmLibraryWrapperImpl(wrapperLibraryPath).getInstance();
        } catch (Exception e) {
            throw new BKPInternalRuntimeException("Failed to link SPDM Wrapper library.", e);
        }
    }

    @Override
    protected byte[] getCertChain() {
        return qkyChainProvider.getChain();
    }

    @Override
    public void close() throws Exception {
        super.close();
        jnaInterface = null;
    }
}
