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

#ifndef COMMANDHEADER_H
#define COMMANDHEADER_H

#include <stddef.h>
#include <vector>

enum SDM_COMMAND_CODE
{
    CERTIFICATE = 0x0B,
    GET_JTAG_IDCODE = 0x10,
    GET_CHIPID = 0x12,
    QSPI_OPEN = 0x32,
    QSPI_CLOSE = 0x33,
    QSPI_SET_CS = 0x34,
    QSPI_ERASE = 0x38,
    QSPI_WRITE = 0x39,
    QSPI_READ = 0x3A,
    GET_ATTESTATION_CERTIFICATE = 0x181,
    CREATE_ATTESTATION_SUBKEY = 0x182,
    GET_MEASUREMENT = 0x183,
    MCTP = 0x194,
    GET_DEVICE_IDENTITY = 0x500
};

enum SDM_RESPONSE_CODE
{
    OK = 0,                               //0
    INVALID_CMD,                          //1
    UNKNOWN_BR,                           //2
    UNKNOWN,                              //3
    INVALID_COMMAND_PARAMS    = 0x04,     //4
    CMD_INVALID_ON_SOURCE     = 0x06,     //6
    CLIENT_ID_NO_MATCH        = 0x08,     //8
    INVALID_ADDRESS           = 0x09,     //9
    AUTHENTICATION_FAIL       = 0x0A,     //10
    TIMEOUT                   = 0x0B,     //11
    HW_NOT_READY              = 0x0C,     //12
    HW_ERROR                  = 0x0D,     //13
    SYNC_LOST                 = 0x0E,     //14
    FUNCTION_NOT_SUPPORT      = 0x0F,     //15

    QSPI_HW_ERROR             = 0x080,    //128
    QSPI_ALREADY_OPEN         = 0x081,    //129
    EFUSE_SYSTEM_FAILURE      = 0x082,    //130

    NOT_CONFIGURED            = 0x100,    //256
    DEVICE_BUSY               = 0x1FF,    //511
    FLASH_ACCESS_DENIED       = 0x2FF,    //767
    NO_VALID_RESP_AVAILABLE   = 0x2FF,    //767
    RESPONSE_ERROR            = 0x3FF,    //1023

    //INTEL PUF
    INTEL_PUF_ACTIVATION_FAILED = 0x510,  //1296
    PUF_HELPER_FILE_READ_ERROR  = 0x511,  //1297
    NOT_PROVISIONED_TO_USE_INTEL_PUF  = 0x512,  //1298
    NOT_FUSED_FOR_INTEL_PUF     = 0x513,  //1299
    UDS_EFUSE_ERROR             = 0x514,  //1300

    // Always add the new enum before here
    LAST
};

class CommandHeader
{
    public:
        void parse(std::vector<uint8_t> &buffer);
        void encode(std::vector<uint8_t> &buffer);
        uint32_t toUint32();
        static size_t getRequiredSize()
        {
            return sizeof(uint32_t);
        }

        uint8_t client = 0;
        uint8_t id = 0;
        uint8_t res1 = 0;
        uint16_t length = 0;
        uint8_t res2 = 0;
        uint16_t code = 0;

    private:
        void fromUint32(uint32_t input);
        uint32_t readBits(uint32_t &source, uint8_t numberOfBits);
        void writeBits(
            uint32_t &destination,
            uint32_t source,
            uint8_t numberOfBits);
};

#endif /* COMMANDHEADER_H */
