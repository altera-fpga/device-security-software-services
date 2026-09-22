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
#ifndef FCS_COMMUNICATION_FCS_IOCTL_H
#define FCS_COMMUNICATION_FCS_IOCTL_H

#include "FcsCommunication.h"
#include "altera_fcs-ioctl.h"
#include "altera_fcs_structs.h"

class FcsCommunicationFcsIoctl: public FcsCommunication
{
    public:
        FcsCommunicationFcsIoctl() {}
        ~FcsCommunicationFcsIoctl() {}

        bool runCommandCode(VerifierProtocol verifierProtocol, std::vector<uint8_t>& responseBuffer, int32_t& statusReturnedFromFcs) override;
        static bool getChipId(std::vector<uint8_t>& outBuffer, int32_t& fcsStatus);
        static bool getMeasurement(
                std::vector<uint8_t> inBuffer,
                std::vector<uint8_t>& outBuffer,
                int32_t& fcsStatus);
        static bool getAttestationCertificate(
                uint8_t certificateRequest,
                std::vector<uint8_t>& outBuffer,
                int32_t& fcsStatus);
        static bool createAttestationSubkey(
                std::vector<uint8_t> inBuffer,
                std::vector<uint8_t>& outBuffer,
                int32_t& fcsStatus);
        static bool mailboxGeneric(
                uint32_t commandCode,
                std::vector<uint8_t> inBuffer,
                std::vector<uint8_t>& outBuffer,
                int32_t& fcsStatus);

    private:
        static bool sendIoctl(altera_fcs_dev_ioctl* data, unsigned long CommandCode);
};

#endif /* FCS_COMMUNICATION_FCS_IOCTL_H */
