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
#ifndef FCS_COMMUNICATION_SPDM_H
#define FCS_COMMUNICATION_SPDM_H

#include "FcsCommunication.h"
#include "altera_fcs-lib.h"
#include "altera_fcs_structs.h"

class FcsCommunicationFcsLib: public FcsCommunication
{
    public:
        FcsCommunicationFcsLib() { initLibrary(); }
        ~FcsCommunicationFcsLib() {}
        bool runCommandCode(VerifierProtocol verifierProtocol, std::vector<uint8_t>& responseBuffer, int32_t& statusReturnedFromFcs);
        bool getChipId(std::vector<uint8_t>& outBuffer, int32_t &fcsStatus);
        bool getJtagIdCode(std::vector<uint8_t>& outBuffer, int32_t& fcsStatus);
        bool getDeviceIdentity(std::vector<uint8_t>& outBuffer, int32_t& fcsStatus);
        bool qspiOpen(int32_t& fcsStatus);
        bool qspiClose(int32_t& fcsStatus);
        bool qspiErase(std::vector<uint8_t> inBuffer, int32_t& fcsStatus);
        bool qspiSetCS(std::vector<uint8_t> inBuffer, int32_t& fcsStatus);
        bool qspiRead(std::vector<uint8_t> inBuffer, std::vector<uint8_t>& outBuffer, int32_t& fcsStatus);
        bool qspiWrite(std::vector<uint8_t> inBuffer, int32_t& fcsStatus);
        bool getAttestationCertificate(
                uint8_t certificateRequest,
                std::vector<uint8_t>& outBuffer,
                int32_t& fcsStatus);
        bool sendMCTP(
                std::vector<uint8_t> inBuffer,
                std::vector<uint8_t>& outBuffer,
                int32_t& fcsStatus);
        void initLibrary();

    private:
        typedef void* LIBFCS_LIB;
        LIBFCS_LIB libFcsLibrary = (LIBFCS_LIB) (nullptr);
        int (*fcs_get_jtag_idcode) (uint32_t*) = nullptr;
        int (*fcs_get_chip_id) (uint32_t*, uint32_t*) = nullptr;
        int (*fcs_attestation_get_certificate) (int, char*, uint32_t*) = nullptr;
        int (*fcs_mctp_cmd_send) (char*, int, char*, int*) = nullptr;
        int (*fcs_get_device_identity) (char*, int*) = nullptr;
        int (*fcs_qspi_open) () = nullptr;
        int (*fcs_qspi_close) () = nullptr;
        int (*fcs_qspi_set_cs) (uint32_t) = nullptr;
        int (*fcs_qspi_erase) (uint32_t, uint32_t) = nullptr;
        int (*fcs_qspi_read) (uint32_t, char*, uint32_t) = nullptr;
        int (*fcs_qspi_write) (uint32_t, char*, uint32_t) = nullptr;
        int (*libfcs_init) (char*) = nullptr;
};

#endif /* FCS_COMMUNICATION_SPDM_H */
