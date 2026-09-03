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

#include "FcsCommunicationFcsIoctl.h"
#include "FcsSimulator.h"

TEST(FcsCommunicationFcsIoctlUT, altera_fcs_dev_ioctlSizeTest)
{
    EXPECT_EQ((size_t)256, sizeof(altera_fcs_dev_ioctl));
}

TEST(FcsCommunicationFcsIoctlUT, getChipIdTest)
{
    std::vector<uint8_t> expectedPayload {0x5A, 0xEC, 0xAC, 0x18, 0xCC, 0xC6, 0x82, 0x07};
    std::vector<uint8_t> payload;
    int32_t status;
    EXPECT_TRUE(FcsCommunicationFcsIoctl::getChipId(payload, status));
    EXPECT_EQ(0, status);
    EXPECT_EQ(expectedPayload, payload);
}

TEST(FcsCommunicationFcsIoctlUT, sigmaTeardownTest)
{
    FcsSimulator::expectedSessionId = 0xFFFFFFFF;
    int32_t status;
    EXPECT_TRUE(FcsCommunicationFcsIoctl::sigmaTeardown(FcsSimulator::expectedSessionId, status));
    EXPECT_EQ(0, status);
    EXPECT_TRUE(FcsCommunicationFcsIoctl::sigmaTeardown(0xAAAA, status));
    EXPECT_EQ(-1, status);
}

TEST(FcsCommunicationFcsIoctlUT, createAttestationSubkeyTest)
{
    FcsSimulator::expectedCreateSubkeyCommandLength = 1000;
    std::vector<uint8_t> payload(FcsSimulator::expectedCreateSubkeyCommandLength, 0x11);
    std::vector<uint8_t> output;
    int32_t status;
    EXPECT_TRUE(FcsCommunicationFcsIoctl::createAttestationSubkey(payload, output, status));
    EXPECT_EQ(0, status);
    EXPECT_EQ((size_t)ATTESTATION_SUBKEY_RSP_MAX_SZ, output.size());
}

TEST(FcsCommunicationFcsIoctlUT, getMeasurementTest)
{
    FcsSimulator::expectedGetMeasurementCommandLength = 2000;
    std::vector<uint8_t> payload(FcsSimulator::expectedGetMeasurementCommandLength, 0x11);
    std::vector<uint8_t> output;
    int32_t status;
    EXPECT_TRUE(FcsCommunicationFcsIoctl::getMeasurement(payload, output, status));
    EXPECT_EQ(0, status);
    EXPECT_EQ(FcsSimulator::expectedGetMeasurementResponseLength, output.size());
}

TEST(FcsCommunicationFcsIoctlUT, getAttestationCertificateTest)
{
    FcsSimulator::expectedCertificateRequest = 0x03;
    std::vector<uint8_t> output;
    int32_t status;
    EXPECT_TRUE(FcsCommunicationFcsIoctl::getAttestationCertificate(0x03, output, status));
    EXPECT_EQ(0, status);
    EXPECT_EQ(FcsSimulator::expectedGetAttCertResponseLength, output.size());
}
