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

#include "gtest/gtest.h"
#include <vector>

#include "VerifierProtocol.h"

TEST(VerifierProtocolUT, parseMessage_invalidHeader)
{
    std::vector<uint8_t> input {0x12, 0x00, 0x00};
    VerifierProtocol verifierProtocol;
    EXPECT_FALSE(verifierProtocol.parseMessage(input));
    EXPECT_EQ(invalidHeader, verifierProtocol.getErrorCode());
    EXPECT_THROW(verifierProtocol.getCertificateRequest(), std::logic_error);
}

TEST(VerifierProtocolUT, parseMessage_getChipid)
{
    std::vector<uint8_t> input {0x12, 0x00, 0x00, 0x10};
    VerifierProtocol verifierProtocol;
    EXPECT_TRUE(verifierProtocol.parseMessage(input));
    EXPECT_EQ(SDM_COMMAND_CODE::GET_CHIPID, verifierProtocol.getCommandCode());
    EXPECT_EQ((size_t)0, verifierProtocol.getIncomingPayload().size());
    EXPECT_THROW(verifierProtocol.getCertificateRequest(), std::logic_error);
}


TEST(VerifierProtocolUT, parseMessage_createSubkey_lengthMismatch)
{
    //input is one byte longer than specified in header
    std::vector<uint8_t> input {0x82, 0x21, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xff};
    VerifierProtocol verifierProtocol;
    EXPECT_FALSE(verifierProtocol.parseMessage(input));
    EXPECT_EQ(invalidHeader, verifierProtocol.getErrorCode());
    EXPECT_THROW(verifierProtocol.getCertificateRequest(), std::logic_error);
}

TEST(VerifierProtocolUT, parseMessage_createSubkey)
{
    std::vector<uint8_t> input {0x82, 0x21, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd};
    VerifierProtocol verifierProtocol;
    EXPECT_TRUE(verifierProtocol.parseMessage(input));
    EXPECT_EQ(SDM_COMMAND_CODE::CREATE_ATTESTATION_SUBKEY, verifierProtocol.getCommandCode());
    EXPECT_THROW(verifierProtocol.getCertificateRequest(), std::logic_error);
    std::vector<uint8_t> expectedPayload{0xaa, 0xbb, 0xcc, 0xdd};
    EXPECT_EQ(expectedPayload, verifierProtocol.getIncomingPayload());
}

TEST(VerifierProtocolUT, parseMessage_getMeasurement)
{
    std::vector<uint8_t> input {0x83, 0x21, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd};
    VerifierProtocol verifierProtocol;
    EXPECT_TRUE(verifierProtocol.parseMessage(input));
    EXPECT_EQ(SDM_COMMAND_CODE::GET_MEASUREMENT, verifierProtocol.getCommandCode());
    EXPECT_THROW(verifierProtocol.getCertificateRequest(), std::logic_error);
    std::vector<uint8_t> expectedPayload{0xaa, 0xbb, 0xcc, 0xdd};
    EXPECT_EQ(expectedPayload, verifierProtocol.getIncomingPayload());
}

TEST(VerifierProtocolUT, parseMessage_getCertificate)
{
    std::vector<uint8_t> input {0x81, 0x11, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00};
    VerifierProtocol verifierProtocol;
    EXPECT_TRUE(verifierProtocol.parseMessage(input));
    EXPECT_EQ(SDM_COMMAND_CODE::GET_ATTESTATION_CERTIFICATE, verifierProtocol.getCommandCode());
    EXPECT_EQ((uint8_t)1, verifierProtocol.getCertificateRequest());
}

TEST(VerifierProtocolUT, parseMessage_getCertificate_reservedBitsSet)
{
    std::vector<uint8_t> input {0x81, 0x11, 0x00, 0x10, 0xE1, 0xFF, 0xFF, 0xFF};
    VerifierProtocol verifierProtocol;
    EXPECT_TRUE(verifierProtocol.parseMessage(input));
    EXPECT_EQ(SDM_COMMAND_CODE::GET_ATTESTATION_CERTIFICATE, verifierProtocol.getCommandCode());
    EXPECT_EQ((uint8_t)0xE1, verifierProtocol.getCertificateRequest());
}

TEST(VerifierProtocolUT, prepareEmptyResponseMessage)
{
    std::vector<uint8_t> incommingMessage {0x12, 0x00, 0x00, 0x10};
    VerifierProtocol verifierProtocol;
    verifierProtocol.parseMessage(incommingMessage);

    std::vector<uint8_t> expectedOutput {0x01, 0x00, 0x00, 0x10};
    std::vector<uint8_t> output;
    verifierProtocol.prepareEmptyResponseMessage(output, genericError);
    EXPECT_EQ(expectedOutput, output);
}

TEST(VerifierProtocolUT, prepareResponseMessage_payloadBufferNotDivisibleByWordSize)
{
    std::vector<uint8_t> incommingMessage {0x12, 0x00, 0x00, 0x10};
    VerifierProtocol verifierProtocol;
    verifierProtocol.parseMessage(incommingMessage);

    std::vector<uint8_t> expectedOutput {0x01, 0x00, 0x00, 0x10};
    std::vector<uint8_t> output;
    std::vector<uint8_t> payload {0xAA, 0xBB, 0xCC};
    verifierProtocol.prepareResponseMessage(payload, output, noError);
    EXPECT_EQ(expectedOutput, output);
}

TEST(VerifierProtocolUT, prepareResponseMessage_withZeroSizePayload)
{
    std::vector<uint8_t> incommingMessage {0x12, 0x00, 0x00, 0x10};
    VerifierProtocol verifierProtocol;
    verifierProtocol.parseMessage(incommingMessage);

    std::vector<uint8_t> expectedOutput {0x00, 0x00, 0x00, 0x10};
    std::vector<uint8_t> output;
    std::vector<uint8_t> payload;
    verifierProtocol.prepareResponseMessage(payload, output, noError);
    EXPECT_EQ(expectedOutput, output);
}

TEST(VerifierProtocolUT, prepareResponseMessage_withPayload)
{
    std::vector<uint8_t> incommingMessage {0x12, 0x00, 0x00, 0x10};
    VerifierProtocol verifierProtocol;
    verifierProtocol.parseMessage(incommingMessage);

    std::vector<uint8_t> expectedOutput {0x00, 0x20, 0x00, 0x10, 0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD};
    std::vector<uint8_t> output;
    std::vector<uint8_t> payload {0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD};
    verifierProtocol.prepareResponseMessage(payload, output, noError);
    EXPECT_EQ(expectedOutput, output);
}

TEST(VerifierProtocolUT, parseMessage_mctp)
{
    std::vector<uint8_t> input {0x94, 0x21, 0x00, 0x10, 0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD};
    std::vector<uint8_t> expectedPayload{0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD};

    VerifierProtocol verifierProtocol;
    EXPECT_TRUE(verifierProtocol.parseMessage(input));

    EXPECT_EQ(SDM_COMMAND_CODE::MCTP, verifierProtocol.getCommandCode());
    EXPECT_THROW(verifierProtocol.getCertificateRequest(), std::logic_error);
    EXPECT_EQ(expectedPayload, verifierProtocol.getIncomingPayload());
}

TEST(VerifierProtocolUT, parseMessage_getIdCode)
{
    std::vector<uint8_t> input {0x10, 0x00, 0x00, 0x10};
    VerifierProtocol verifierProtocol;
    EXPECT_TRUE(verifierProtocol.parseMessage(input));
    EXPECT_EQ(SDM_COMMAND_CODE::GET_JTAG_IDCODE, verifierProtocol.getCommandCode());
    EXPECT_EQ((size_t)0, verifierProtocol.getIncomingPayload().size());
    EXPECT_THROW(verifierProtocol.getCertificateRequest(), std::logic_error);
}

TEST(VerifierProtocolUT, parseMessage_getDeviceIdentity)
{
    std::vector<uint8_t> input {0x00, 0x05, 0x00, 0x10};
    VerifierProtocol verifierProtocol;
    EXPECT_TRUE(verifierProtocol.parseMessage(input));
    EXPECT_EQ(SDM_COMMAND_CODE::GET_DEVICE_IDENTITY, verifierProtocol.getCommandCode());
    EXPECT_EQ((size_t)0, verifierProtocol.getIncomingPayload().size());
    EXPECT_THROW(verifierProtocol.getCertificateRequest(), std::logic_error);
}
