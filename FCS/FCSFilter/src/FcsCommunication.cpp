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

#include "FcsCommunicationFcsIoctl.h"
#include "FcsCommunicationFcsLib.h"

FcsCommunication* FcsCommunication::getFcsCommunication() {
    FcsCommunication* instance = nullptr;
    try {
        Logger::log("Use FCS library for communication.");
        instance = new FcsCommunicationFcsLib();
    } catch (const FcsLibraryException& ex) {
        Logger::log(ex.what(), Warning);
        Logger::log("Failed to find FCS library from HPS image. This may due to the device is not Agilex 5. So, the library is missing from the image. Switch to use FCS Ioctl for communication.", Warning);
        instance = new FcsCommunicationFcsIoctl();
    }
    return instance;
}

std::string FcsCommunication::get_mailbox_name(uint32_t CommandCode)
{
    std::map<uint32_t, std::string, std::less<uint32_t>> FCS_COMMUNICATION_CMD_MAP =
    {
        {SDM_COMMAND_CODE::CERTIFICATE, "CERTIFICATE"},
        {SDM_COMMAND_CODE::GET_JTAG_IDCODE, "GET_JTAG_IDCODE"},
        {SDM_COMMAND_CODE::GET_CHIPID, "GET_CHIPID"},
        {SDM_COMMAND_CODE::GET_DEVICE_IDENTITY, "GET_DEVICE_IDENTITY"},
        {SDM_COMMAND_CODE::GET_ATTESTATION_CERTIFICATE, "GET_ATTESTATION_CERTIFICATE"},
        {SDM_COMMAND_CODE::QSPI_OPEN, "QSPI_OPEN"},
        {SDM_COMMAND_CODE::QSPI_CLOSE, "QSPI_CLOSE"},
        {SDM_COMMAND_CODE::QSPI_SET_CS, "QSPI_SET_CS"},
        {SDM_COMMAND_CODE::QSPI_ERASE, "QSPI_ERASE"},
        {SDM_COMMAND_CODE::QSPI_READ, "QSPI_READ"},
        {SDM_COMMAND_CODE::QSPI_WRITE, "QSPI_WRITE"},
        {SDM_COMMAND_CODE::MCTP, "MCTP"},
        {SDM_COMMAND_CODE::CREATE_ATTESTATION_SUBKEY, "CREATE_ATTESTATION_SUBKEY"},
        {SDM_COMMAND_CODE::GET_MEASUREMENT, "GET_MEASUREMENT"},
    };
    auto it = FCS_COMMUNICATION_CMD_MAP.find(CommandCode);
    if (it != FCS_COMMUNICATION_CMD_MAP.end())
    {
        return it->second;
    }

    std::ostringstream stream;
    stream << "0x" << std::hex << std::setw(8) << std::setfill('0') << CommandCode;
    return stream.str();
}
