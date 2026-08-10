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

package com.intel.bkp.bkps.rest.initialization;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class InitializationResource {

    private static final String VERSION = "/v1";
    public static final String INIT_NODE = "/init" + VERSION;

    public static final String IMPORT_KEY = "/import-key";

    public static final String SIGNING_KEY = "/signing-key";
    public static final String SIGNING_KEY_LIST = SIGNING_KEY + "/list";
    public static final String SIGNING_KEY_ACTIVATE = SIGNING_KEY + "/activate/{signingKeyId}";
    public static final String SIGNING_KEY_PUB_KEY = SIGNING_KEY + "/{signingKeyId}";
    public static final String SIGNING_KEY_UPLOAD = SIGNING_KEY + "/upload/{signingKeyId}";
    public static final String ROOT_SIGNING_KEY = "/root-signing-key";

    private static final String SEALING_KEY = "/sealing-key";
    public static final String SEALING_KEY_BASE = INIT_NODE + SEALING_KEY;
    public static final String SEALING_KEY_ROTATE = "/rotate";
    public static final String SEALING_KEY_BACKUP = "/backup";
    public static final String SEALING_KEY_RESTORE = "/restore";

    private static final String CONTEXT_KEY = "/context-key";
    public static final String CONTEXT_KEY_ROTATE = CONTEXT_KEY + SEALING_KEY_ROTATE;
}
