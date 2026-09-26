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

#include "Logger.h"
#include "utils.h"
#include "VerifierProtocol.h"

bool VerifierProtocol::parseMessage(std::vector<uint8_t> &messageBuffer)
{
    if (messageBuffer.size() < CommandHeader::getRequiredSize())
    {
        Logger::log("Message Size is smaller than Command Header", Error);
        errorCode = invalidHeader;
        return false;
    }
    incomingHeader.parse(messageBuffer);

    size_t actualDataSizeInBytes = messageBuffer.size() - CommandHeader::getRequiredSize();
    size_t dataSizeFromHeaderInBytes = incomingHeader.length * WORD_SIZE;
    if (actualDataSizeInBytes != dataSizeFromHeaderInBytes)
    {
        Logger::log("Data length received from network (bytes): "
            + std::to_string(actualDataSizeInBytes)
            + " is not equal to size specified in command header (converted from word to bytes): "
            + std::to_string(dataSizeFromHeaderInBytes), Error);
        errorCode = invalidHeader;
        return false;
    }

    size_t payloadOffset = getPayloadOffset();

    if (messageBuffer.size() < payloadOffset)
    {
        Logger::log("Message Size too small", Error);
        errorCode = invalidHeader;
        return false;
    }

    incomingPayload = std::vector<uint8_t>(
        messageBuffer.begin() + payloadOffset,
        messageBuffer.end());
    if (!isPayloadSizeCorrect() || !isMagicWordCorrect())
    {
        return false;
    }
    errorCode = noError;
    return true;
}

size_t VerifierProtocol::getPayloadOffset()
{
    size_t messageReservedBytesCount = 0;
    if (incomingHeader.code == SDM_COMMAND_CODE::CREATE_ATTESTATION_SUBKEY
        || incomingHeader.code == SDM_COMMAND_CODE::GET_MEASUREMENT
        )
    {
        messageReservedBytesCount = RESERVED_BYTES_COUNT;
    }

    return CommandHeader::getRequiredSize() + messageReservedBytesCount;
}

bool VerifierProtocol::isPayloadSizeCorrect()
{
    auto itr = payloadSizeMap.find(incomingHeader.code);
    if (itr != payloadSizeMap.end() && itr->second != incomingPayload.size())
    {
        Logger::log("Message Size incorrect", Error);
        errorCode = invalidHeader;
        return false;
    }
    return true;
}

bool VerifierProtocol::isMagicWordCorrect()
{
    return true;
}

void VerifierProtocol::prepareEmptyResponseMessage(
    std::vector<uint8_t> &responseBuffer,
    const int returnCode)
{
    prepareResponseMessage(std::vector<uint8_t>(), responseBuffer, returnCode);
}

void VerifierProtocol::prepareResponseMessage(
    std::vector<uint8_t> const &payloadBuffer,
    std::vector<uint8_t> &responseBuffer,
    const int returnCode)
{
    Logger::log("Preparing response with return code "
        + std::to_string(returnCode));
    if (payloadBuffer.size() % WORD_SIZE != 0)
    {
        Logger::log("Payload size not divisible by word size", Error);
        prepareEmptyResponseMessage(responseBuffer, genericError);
        return;
    }

    CommandHeader outgoingHeader;
    outgoingHeader.client = incomingHeader.client;
    outgoingHeader.id = incomingHeader.id;
    outgoingHeader.length = payloadBuffer.size() / WORD_SIZE;
    outgoingHeader.res1 = 0;
    outgoingHeader.res2 = 0;
    outgoingHeader.code = returnCode;

    responseBuffer.reserve(CommandHeader::getRequiredSize() + payloadBuffer.size());
    responseBuffer.resize(CommandHeader::getRequiredSize());

    Logger::log("encoding header", Debug);
    outgoingHeader.encode(responseBuffer);

    if (payloadBuffer.size() > 0)
    {
        Logger::log("copying payload to response buffer", Debug);
        std::copy(
            payloadBuffer.begin(),
            payloadBuffer.end(),
            std::back_inserter(responseBuffer));
    }

}

uint32_t VerifierProtocol::getCommandCode()
{
    return incomingHeader.code;
}


uint8_t VerifierProtocol::getCertificateRequest()
{
    //should never happen
    if (getCommandCode() != SDM_COMMAND_CODE::GET_ATTESTATION_CERTIFICATE)
    {
        throw std::logic_error("Attempt to read certificate request from message of type other than getAttestationCertificate");
    }

    //should never happen, as it is also checked during parsing
    if (incomingPayload.size() < payloadSizeMap[SDM_COMMAND_CODE::GET_ATTESTATION_CERTIFICATE])
    {
        throw std::logic_error("getCertificateRequest: Message Size too small");
    }
    uint32_t getAttCertPayload = Utils::decodeFromLittleEndianBuffer(incomingPayload);
    return  getAttCertPayload & GET_ATT_CERT_CERTIFICATE_REQUEST_MASK;
}
