/*
 This project, FPGA Crypto Service Server, is licensed as below

 ***************************************************************************

 Copyright 2020-2025 Altera Corporation. All Rights Reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 ***************************************************************************
 */

#include "FcsCommunication.h"
#include "Qspi.h"
#include "CommandHeader.h"
#include <stdexcept>

bool Qspi::callFcs(uint32_t commandCode,
             std::vector<uint8_t>& inBuffer,
             std::vector<uint8_t>& outBuffer,
             std::string functionName)
{
    bool status = true;
    int32_t statusReturnedFromFcs = -1;
    std::string payloadHex;
    for (auto byteValue : inBuffer)
    {
        payloadHex += Utils::toHexString(byteValue) + " ";
    }
    Logger::log("Calling FCS. Payload: " + payloadHex, Debug);
    FcsCommunication* fcsCommunication = FcsCommunication::getFcsCommunication();
    if (fcsCommunication == nullptr)
    {
        return false;
    }

    VerifierProtocol verifierProtocol;
    verifierProtocol.setCommandCode(commandCode);
    verifierProtocol.setIncomingPayload(inBuffer);
    if (!fcsCommunication->runCommandCode(verifierProtocol, outBuffer, statusReturnedFromFcs))
    {
        Logger::log(functionName + ": FCS call failed.", Error);
        status = false;
    }
    if (status && statusReturnedFromFcs != 0)
    {
        std::string err_desc = decode_sdm_response_error_code(statusReturnedFromFcs);
        Logger::log(err_desc, Error);
        status = false;
    }

    if (status)
    {
        std::string outputHex;
        for (auto byteValue : outBuffer)
        {
            outputHex += Utils::toHexString(byteValue) + " ";
        }
        Logger::log("Output from FCS: " + outputHex, Debug);
    }
    return status;
}

std::string Qspi::decode_sdm_response_error_code(uint32_t error_code)
{
    std::string err_code_hex = Utils::toHexString(error_code);
    std::string description(err_code_hex);
    switch(error_code)
    {
        case SDM_RESPONSE_CODE::OK:
            description += "The command completed successfully.";
            break;
        case SDM_RESPONSE_CODE::INVALID_CMD:
        case SDM_RESPONSE_CODE::UNKNOWN_BR:
            description += "The currently loaded boot ROM cannot decode or recognize the command code.";
            break;
        case SDM_RESPONSE_CODE::UNKNOWN:
            description += "The currently loaded firmware cannot decode the command code.";
            break;
        case SDM_RESPONSE_CODE::INVALID_COMMAND_PARAMS:
            description += "The command is incorrectly formatted.";
            break;
        case SDM_RESPONSE_CODE::CMD_INVALID_ON_SOURCE:
            description += "The command is from a source for which it is not enabled.";
            break;
        case SDM_RESPONSE_CODE::CLIENT_ID_NO_MATCH:
            description += "The client ID does not match the existing client with the current exclusive access to quad SPI.";
            break;
        case SDM_RESPONSE_CODE::INVALID_ADDRESS:
            description += "The address is invalid.";
            break;
        case SDM_RESPONSE_CODE::AUTHENTICATION_FAIL:
            description += "The configuration bitstream signature authentication failure.";
            break;
        case SDM_RESPONSE_CODE::TIMEOUT:
            description += "Command timed out.";
            break;
        case SDM_RESPONSE_CODE::HW_NOT_READY:
            description += "The hardware is not ready due to either an initialization or configuration problem.";
            break;
        case SDM_RESPONSE_CODE::HW_ERROR:
            description += "The command unable to complete due to unrecoverable hardware error.";
            break;
        case SDM_RESPONSE_CODE::SYNC_LOST:
            description += "The device is out of sync after recovery reset.";
            break;
        case SDM_RESPONSE_CODE::FUNCTION_NOT_SUPPORT:
            description += "The function is currently not supported.";
            break;

        case SDM_RESPONSE_CODE::QSPI_HW_ERROR:
            description += "Indicates QSPI flash memory error. This error indicates one of the following conditions:\n1. A QSPI flash chip select setting problem\n2. A QSPI flash initialization problem\n3. A QSPI flash resetting problem\n4. A QSPI flash settings update problem";
            break;
        case SDM_RESPONSE_CODE::QSPI_ALREADY_OPEN:
            description += "The client's exclusive access to QSPI flash via QSPI_OPEN command is already open.";
            break;
        case SDM_RESPONSE_CODE::EFUSE_SYSTEM_FAILURE:
            description += "The eFuse cache pointer is invalid.";
            break;

        case SDM_RESPONSE_CODE::NOT_CONFIGURED:
            description += "The device is not configured.";
            break;
        case SDM_RESPONSE_CODE::DEVICE_BUSY:
            description += "The device is busy due to following use cases:\n1. RSU: Firmware is unable to transition to different version due to an internal error.\n2. HPS: HPS is busy when in HPS reconfiguration process or HPS cold reset.";
            break;
        case SDM_RESPONSE_CODE::NO_VALID_RESP_AVAILABLE:
            description += "There is no valid response available.";
            break;
        case SDM_RESPONSE_CODE::RESPONSE_ERROR :
            description += "General Error.";
            break;
        default:
            description += "Unknown error.";
            Logger::log("Detected unknown error code " + err_code_hex, Fatal);
            break;
    }
    return description;
}

bool Qspi::qspiOpen()
{
    Logger::log("QSPI Open", Debug);
    std::vector<uint8_t> request;
    std::vector<uint8_t> response;
    return callFcs(SDM_COMMAND_CODE::QSPI_OPEN, request, response, "qspiOpen");
}

bool Qspi::qspiClose()
{
    Logger::log("QSPI Close", Debug);
    std::vector<uint8_t> request;
    std::vector<uint8_t> response;
    return callFcs(SDM_COMMAND_CODE::QSPI_CLOSE, request, response, "qspiClose");
}

bool Qspi::qspiSetCs(uint8_t cs, bool mode, bool ca)
{
    Logger::log("QSPI Set CS", Debug);
    if (cs > 0xF)
    {
        throw std::invalid_argument("CS should fit on 4 bits");
    }

    uint32_t payload = 0;
    payload |= cs << 28;
    payload |= mode << 27;
    payload |= ca << 26;
    std::vector<uint8_t> request(sizeof(uint32_t), 0);
    Utils::encodeToLittleEndianBuffer(payload, request);

    std::vector<uint8_t> response;

    return callFcs(SDM_COMMAND_CODE::QSPI_SET_CS, request, response, "qspiSetCs");
}

bool Qspi::qspiErase(uint32_t address, uint32_t sizeInWords)
{
    if (!is4kAligned(address))
    {
        throw std::invalid_argument("qspiErase: address should be aligned to 4KB");
    }
    if (!is4kAligned(sizeInWords))
    {
        throw std::invalid_argument("qspiErase: size should be aligned to 4KB");
    }
    std::vector<uint8_t> request(2 * sizeof(uint32_t), 0);
    Utils::encodeToLittleEndianBuffer(address, request);
    Utils::encodeToLittleEndianBuffer(sizeInWords, request, sizeof(uint32_t));
    std::vector<uint8_t> response;
    return callFcs(SDM_COMMAND_CODE::QSPI_ERASE, request, response, "qspiErase");
}

bool Qspi::qspiReadMultiple(uint32_t address, uint32_t sizeInWords, std::vector<uint8_t>& outBuffer)
{
    uint32_t wordsLeft = sizeInWords;
    bool status = true;
    do
    {
        uint32_t wordsToRead = wordsLeft > maxTransferSizeInWords ? maxTransferSizeInWords : wordsLeft;
        std::vector<uint8_t> readBuffer(wordsToRead * WORD_SIZE);
        uint32_t byteOffset = (sizeInWords - wordsLeft) * WORD_SIZE;
        status  = qspiRead(address + byteOffset, wordsToRead, readBuffer);
        std::copy(
                readBuffer.begin(),
                readBuffer.end(),
                std::back_inserter(outBuffer));
        wordsLeft -= wordsToRead;
    } while (status && wordsLeft > 0);
    return status;
}

bool Qspi::qspiWriteMultiple(uint32_t address, uint32_t sizeInWords, std::vector<uint8_t>& inBuffer)
{
    uint32_t wordsLeft = sizeInWords;
    bool status = true;
    do
    {
        uint32_t wordsToWrite = wordsLeft > maxTransferSizeInWords ? maxTransferSizeInWords : wordsLeft;
        std::vector<uint8_t> writeBuffer;
        uint32_t byteOffset = (sizeInWords - wordsLeft) * WORD_SIZE;
        std::copy(
                inBuffer.begin() + byteOffset,
                inBuffer.begin() + byteOffset + (wordsToWrite * WORD_SIZE),
                std::back_inserter(writeBuffer));
        status = qspiWrite(address + byteOffset, wordsToWrite, writeBuffer);
        wordsLeft -= wordsToWrite;
    } while (status && wordsLeft > 0);
    return status;
}

bool Qspi::qspiRead(uint32_t address, uint32_t sizeInWords, std::vector<uint8_t>& outBuffer)
{
    std::vector<uint8_t> request(2 * sizeof(uint32_t));
    Utils::encodeToLittleEndianBuffer(address, request);
    Utils::encodeToLittleEndianBuffer(sizeInWords, request, sizeof(uint32_t));
    Logger::log("qspiRead called. Address: " + Utils::toHexString(address) +
                " Length in words: " + Utils::toHexString(sizeInWords), Debug);
    bool status = callFcs(SDM_COMMAND_CODE::QSPI_READ, request, outBuffer, "qspiRead");
    if (status && !outBuffer.empty())
    {
        std::vector<uint32_t> output_data = Utils::wordBufferFromByteBuffer(outBuffer);
        status = (output_data.size() == sizeInWords);
    }
    return status;
}

bool Qspi::qspiWrite(uint32_t address, uint32_t sizeInWords, std::vector<uint8_t>& inBuffer)
{
    std::vector<uint8_t> request(2 * sizeof(uint32_t));
    Utils::encodeToLittleEndianBuffer(address, request);
    Utils::encodeToLittleEndianBuffer(sizeInWords, request, sizeof(uint32_t));
    std::copy (inBuffer.begin(), inBuffer.end(), std::back_inserter(request));
    std::vector<uint8_t> response;
    return callFcs(SDM_COMMAND_CODE::QSPI_WRITE, request, response, "qspiWrite");
}

void Qspi::qspiAssert(bool condition, std::string exceptionMessage)
{
     if (!condition)
     {
        throw std::invalid_argument(exceptionMessage);
     }

}

bool Qspi::qspiVerify(uint32_t address, uint32_t sizeInWords, std::vector<uint8_t> inBuffer)
{
    qspiAssert(((address % 4) == 0), "qspiVerify: start address must be word aligned");
    qspiAssert(((sizeInWords % 16) == 0), "qspiVerify: start address must be word aligned");
    qspiAssert(!inBuffer.empty(), "qspiVerify: input buffer should not be empty");
    Logger::log("qspiVerify called. start address = " + Utils::toHexString(address), Debug);
    std::vector<uint8_t> respBuf;
    bool status = qspiReadMultiple(address, sizeInWords, respBuf);
    if (status)
    {
        uint32_t offset = 0;
        for (offset = 0; status && offset < (sizeInWords * 4); offset++)
        {
            status = (inBuffer[offset] == respBuf[offset]);
        }

        if (!status)
        {
            Logger::log("Verification failed at address " + Utils::toHexString(address + offset), Error);
        }
    }

    return status;
}
