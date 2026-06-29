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


import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class LibSpdmCapabilities {

    // REQUESTOR FLAGS
    public static final int SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP = 0x00000002;
    public static final int SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP = 0x00000004;
    public static final int SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP = 0x00000040;
    public static final int SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP = 0x00000080;
    public static final int SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP = 0x00000100;
    public static final int SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP = 0x00000200;
    public static final int SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP = (0x00000400 | 0x00000800);
    public static final int SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER = 0x00000400;
    public static final int SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP = 0x00001000;
    public static final int SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP = 0x00002000;
    public static final int SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP = 0x00004000;
    public static final int SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP = 0x00008000;
    public static final int SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP = 0x00010000;
    public static final int SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP = 0x00020000;

    // RESPONDER FLAGS
    public static final int SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP = 0x00000200;
    public static final int SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP = 0x00080000;
}
