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

#include "MessageHandler.h"
#include "FcsCommunication.h"
#include "Logger.h"
#include "VerifierProtocol.h"

bool handleIncomingMessage(
    std::vector<uint8_t> &messageBuffer,
    std::vector<uint8_t> &responseBuffer)
{
    VerifierProtocol verifierProtocol;
    if (!verifierProtocol.parseMessage(messageBuffer))
    {
        // Error handled by BKPS
        Logger::log("Couldn't parse incoming message", Error);
        verifierProtocol.prepareResponseMessage(
            std::vector<uint8_t>(), responseBuffer, verifierProtocol.getErrorCode());
        return true;
    }
    FcsCommunication* fcsCommunication = FcsCommunication::getFcsCommunication();
    if (fcsCommunication == nullptr)
    {
        Logger::log("FCS communication is not supported on this device.", Error);
        return false;
    }
    int32_t statusReturnedFromFcs = -1;
    fcsCommunication->runCommandCode(verifierProtocol, responseBuffer, statusReturnedFromFcs);

    return true;
}
