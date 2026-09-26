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

#include "CommandHeader.h"
#include "VerifierProtocol.h"

TEST(CommandHeaderUT, parseTest)
{
    //real world example - get_chipid
    std::vector<uint8_t> input {0x12, 0x00, 0x00, 0x10};
    CommandHeader header;
    header.parse(input);
    EXPECT_EQ(0x12, header.code);
    EXPECT_EQ(0x00, header.length);
    EXPECT_EQ(0x01, header.client);
    EXPECT_EQ(0x00, header.id);
    EXPECT_EQ(0x00, header.res1);
    EXPECT_EQ(0x00, header.res2);

    input = std::vector<uint8_t> {0xd5, 0x30, 0x00, 0x12};
    header.parse(input);
    EXPECT_EQ(0xd5, header.code);
    EXPECT_EQ(0x03, header.length);
    EXPECT_EQ(0x01, header.client);
    EXPECT_EQ(0x02, header.id);
    EXPECT_EQ(0x00, header.res1);
    EXPECT_EQ(0x00, header.res2);

    //same as above, but with reserved bits set to 1
    input = std::vector<uint8_t> {0xd5, 0x38, 0x80, 0x12};
    header.parse(input);
    EXPECT_EQ(0xd5, header.code);
    EXPECT_EQ(0x03, header.length);
    EXPECT_EQ(0x01, header.client);
    EXPECT_EQ(0x02, header.id);
    EXPECT_EQ(0x01, header.res1);
    EXPECT_EQ(0x01, header.res2);

    //large values that cross byte boundaries with unique hex digits for easier checking
    input = std::vector<uint8_t> {0x56, 0x83, 0x47, 0x12};
    header.parse(input);
    EXPECT_EQ(0x356, header.code);
    EXPECT_EQ(0x478, header.length);
    EXPECT_EQ(0x01, header.client);
    EXPECT_EQ(0x02, header.id);
    EXPECT_EQ(0x00, header.res1);
    EXPECT_EQ(0x00, header.res2);
}

TEST(CommandHeaderUT, encodeTest)
{
    //real world example - get_chipid
    std::vector<uint8_t> expectedOutput {0x12, 0x00, 0x00, 0x10};
    std::vector<uint8_t> output(4, 0xFF); //fill buffer with FFs, to make sure that vector's initial content is cleared
    CommandHeader header;
    header.res1 = 0;
    header.res2 = 0;
    header.code = 0x12;
    header.client = 0x01;
    header.id = 0x00;
    header.length = 0x00;
    header.encode(output);
    EXPECT_EQ(expectedOutput, output);

    expectedOutput = std::vector<uint8_t> {0xd5, 0x30, 0x00, 0x12};
    output = std::vector<uint8_t>(4, 0xFF); //fill buffer with FFs, to make sure that vector's initial content is cleared
    header.res1 = 0;
    header.res2 = 0;
    header.code = 0xd5;
    header.client = 0x01;
    header.id = 0x02;
    header.length = 0x03;
    header.encode(output);
    EXPECT_EQ(expectedOutput, output);

    //same as above, but with reserved bits set to 1
    expectedOutput = std::vector<uint8_t> {0xd5, 0x38, 0x80, 0x12};
    output = std::vector<uint8_t>(4, 0xFF); //fill buffer with FFs, to make sure that vector's initial content is cleared
    header.res1 = 1;
    header.res2 = 1;
    header.code = 0xd5;
    header.client = 0x01;
    header.id = 0x02;
    header.length = 0x03;
    header.encode(output);
    EXPECT_EQ(expectedOutput, output);

    //large values that cross byte boundaries with unique hex digits for easier checking
    expectedOutput = std::vector<uint8_t> {0x56, 0x83, 0x47, 0x12};
    output = std::vector<uint8_t>(4, 0xFF); //fill buffer with FFs, to make sure that vector's initial content is cleared
    header.res1 = 0;
    header.res2 = 0;
    header.code = 0x356;
    header.client = 0x01;
    header.id = 0x02;
    header.length = 0x478;
    header.encode(output);
    EXPECT_EQ(expectedOutput, output);
}
