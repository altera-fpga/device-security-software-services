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

#include "quartus/jtag_helper.h"

Status_t JtagHelperImpl::exchange_jtag_cmd_internal(const Message_t messageType,
                                                    const std::string &encodedCommand,
                                                    std::string &outResponse) {
    std::string decodedCommand = decode_command(encodedCommand);

    const auto bufInSizeIn4ByteWords = bytesTo4ByteWords(decodedCommand.length());
    LOG(L_DEBUG, "Decoded command length in 4-byte words: " + std::to_string(bufInSizeIn4ByteWords));

    const auto *inBuffer = reinterpret_cast<const uint32_t *>(decodedCommand.c_str());

    // Allocated data size -> after send_message it will contain actual data in outBuffer
    size_t bufOutSizeIn4ByteWords = BUF_OUT_SIZE_MAX_IN_4BYTE_WORDS;

#ifdef _WIN32
    std::unique_ptr buff = std::make_unique<uint32_t[]>(bufOutSizeIn4ByteWords);
    auto *outBuffer = buff.get();
#else
    ProtectedMemory::Page page(BUF_OUT_SIZE_MAX_IN_BYTES);

    if (!is_page_guarded(page.state())) {
        LOG(L_ERROR, "Buffer for Device response not allocated.");
        outResponse = "";
        return ST_GENERIC_ERROR;
    }

    auto *outBuffer = static_cast<uint32_t *>(page.get());
#endif // _WIN32
    LOG(L_DEBUG, "Sending JTAG command to device...");
    auto result = qc->send_message(messageType, inBuffer, bufInSizeIn4ByteWords, &outBuffer, bufOutSizeIn4ByteWords);

    if (!is_result_ok(result)) {
        LOG(L_ERROR, "Device responded with status error.");
        outResponse = "";
        return ST_GENERIC_ERROR;
    }

    if (!is_buffer_size_in_range(bufOutSizeIn4ByteWords)) {
        LOG(L_ERROR, "Device tried to write response beyond allocated memory.");
        outResponse = "";
        return ST_GENERIC_ERROR;
    }

    outResponse = prepareResponse(outBuffer, bufOutSizeIn4ByteWords);
    return result;
}

Status_t JtagHelperImpl::exchange_jtag_cmd(const Command &command, std::string &outResponse) {
    return exchange_jtag_cmd_internal(command.type, command.value, outResponse);
}

std::string JtagHelperImpl::prepareResponse(const uint32_t *outBuffer, const size_t bufOutSizeIn4ByteWords) {
    auto response = std::string(reinterpret_cast<const char *> (outBuffer),
                                fourByteWordsToBytes(bufOutSizeIn4ByteWords));
    return encode_command(response);
}

size_t JtagHelperImpl::bytesTo4ByteWords(size_t sizeBytes) {
    const auto result = static_cast<size_t>(sizeBytes / DWORD_SIZE_IN_BYTES);
    return (sizeBytes % DWORD_SIZE_IN_BYTES == 0) ? result : result + 1;
}

size_t JtagHelperImpl::fourByteWordsToBytes(size_t size4ByteWords) {
    return size4ByteWords * DWORD_SIZE_IN_BYTES;
}

#ifndef _WIN32
bool JtagHelperImpl::is_page_guarded(ProtectedMemory::PageState state) {
    return state == ProtectedMemory::PageState::PAGE_GUARDED;
}
#endif // !_WIN32

bool JtagHelperImpl::is_result_ok(Status_t result) {
    return result == ST_OK;
}

bool JtagHelperImpl::is_buffer_size_in_range(size_t bufOutSizeIn4ByteWords) {
    return bufOutSizeIn4ByteWords <= BUF_OUT_SIZE_MAX_IN_4BYTE_WORDS;
}

std::string JtagHelperImpl::encode_command(const std::string &decodedCmd) {
    try {
        std::string encodedCmd = b64_utils::encode64(decodedCmd);
        LOG(L_DEBUG, "JtagResponses from device: " + encodedCmd);
        return encodedCmd;
    }
    catch (const std::exception &ex) {
        std::string exceptionMessage(ex.what());
        std::string internalMessage = str_utils::concat_strings(
                {"Encoding of command failed with message: ", exceptionMessage});
        // If something happens during encoding responses from Device, the flow shall not be halted by Programmer
        // All responses should be collected and send back to BKPS
        LOG(L_ERROR, internalMessage);
    }
    return "";
}

std::string JtagHelperImpl::decode_command(const std::string &encodedCmd) {
    LOG(L_DEBUG, "JtagCommands from Black Key Provisioning Service (BKPS): " + encodedCmd);
    try {
        return b64_utils::decode64(encodedCmd);
    }
    catch (const std::exception &ex) {
        std::string exceptionMessage(ex.what());
        std::string internalMessage = str_utils::concat_strings(
                {"Decoding of command [ ", encodedCmd, " ] failed with message: ", exceptionMessage});
        // If something happens during decoding message from BKPS, the whole flow should stop.
        throw BkpBase64Exception(internalMessage);
    }
}
