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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.model.dto.MessageDTO;
import com.intel.bkp.bkps.programmer.model.dto.ResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.SetAuthorityContext;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class SetAuthorityContextConverter {

    private static final String FAILED_TO_DESERIALIZE_CONTEXT =
        "Failed to deserialize Set Authority Context.";
    private static final String FAILED_TO_SERIALIZE_CONTEXT =
        "Failed to serialize Set Authority Context.";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static List<MessageDTO> encodeMessages(List<ProgrammerMessage> programmerMessages) {
        return programmerMessages.stream().map(MessageDTO::from).collect(Collectors.toList());
    }

    public static List<ProgrammerResponse> decodeResponses(List<ResponseDTO> encodedResponses) {
        return encodedResponses.stream().map(ProgrammerResponse::from).collect(Collectors.toList());
    }

    public static byte[] serialize(Object object) throws IOException {
        try {
            return MAPPER.writeValueAsBytes(object);
        } catch (JsonProcessingException e) {
            throw new IOException(FAILED_TO_SERIALIZE_CONTEXT, e);
        }
    }

    public static SetAuthorityContext deserialize(byte[] context, Class<? extends SetAuthorityContext> type)
        throws IOException {
        return (SetAuthorityContext) deserializeInternal(context, type);
    }

    private static Object deserializeInternal(byte[] context, Class<?> type)
        throws IOException {
        return Optional.ofNullable(MAPPER.readValue(context, type))
            .orElseThrow(() -> new IOException(FAILED_TO_DESERIALIZE_CONTEXT));
    }
}
