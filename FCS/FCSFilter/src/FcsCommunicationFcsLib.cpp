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

#include <dlfcn.h>
#include <cassert>
#include <deque>
#include "FcsCommunicationFcsLib.h"

bool FcsCommunicationFcsLib::runCommandCode(VerifierProtocol verifierProtocol, std::vector<uint8_t>& responseBuffer, int32_t& statusReturnedFromFcs)
{
    bool fcsCallSucceeded = false;
    bool skipPrepareResponseHeader = false;
    std::vector<uint8_t> payloadFromFcs(0);
    Logger::log("Calling "+ get_mailbox_name(verifierProtocol.getCommandCode()));
    switch (verifierProtocol.getCommandCode())
    {
        case SDM_COMMAND_CODE::GET_CHIPID:
        {
            fcsCallSucceeded = getChipId(
                payloadFromFcs,
                statusReturnedFromFcs);
        }
        break;
        case SDM_COMMAND_CODE::GET_JTAG_IDCODE:
        {
            fcsCallSucceeded = getJtagIdCode(
                payloadFromFcs,
                statusReturnedFromFcs);
        }
        break;
        case SDM_COMMAND_CODE::GET_DEVICE_IDENTITY:
        {
            fcsCallSucceeded = getDeviceIdentity(
                payloadFromFcs,
                statusReturnedFromFcs);
        }
        break;
        case SDM_COMMAND_CODE::QSPI_OPEN:
        {
            skipPrepareResponseHeader = true;
            fcsCallSucceeded = qspiOpen(statusReturnedFromFcs);
        }
        break;
        case SDM_COMMAND_CODE::QSPI_CLOSE:
        {
            skipPrepareResponseHeader = true;
            fcsCallSucceeded = qspiClose(statusReturnedFromFcs);
        }
        break;
        case SDM_COMMAND_CODE::QSPI_ERASE:
        {
            skipPrepareResponseHeader = true;
            fcsCallSucceeded = qspiErase(
                verifierProtocol.getIncomingPayload(),
                statusReturnedFromFcs);
        }
        break;
        case SDM_COMMAND_CODE::QSPI_SET_CS:
        {
            skipPrepareResponseHeader = true;
            fcsCallSucceeded = qspiSetCS(
                verifierProtocol.getIncomingPayload(),
                statusReturnedFromFcs);
        }
        break;
        case SDM_COMMAND_CODE::QSPI_READ:
        {
            skipPrepareResponseHeader = true;
            responseBuffer.resize(0);
            fcsCallSucceeded = qspiRead(
                verifierProtocol.getIncomingPayload(),
                payloadFromFcs,
                statusReturnedFromFcs);
        }
        break;
        case SDM_COMMAND_CODE::QSPI_WRITE:
        {
            skipPrepareResponseHeader = true;
            fcsCallSucceeded = qspiWrite(
                verifierProtocol.getIncomingPayload(),
                statusReturnedFromFcs);
        }
        break;
        case SDM_COMMAND_CODE::GET_ATTESTATION_CERTIFICATE:
        {
            fcsCallSucceeded = getAttestationCertificate(
                verifierProtocol.getCertificateRequest(),
                payloadFromFcs,
                statusReturnedFromFcs);
            if (statusReturnedFromFcs == -1)
            {
                Logger::log("GET_ATTESTATION_CERTIFICATE not supported by the driver. Returning unknown command.");
                verifierProtocol.prepareEmptyResponseMessage(
                responseBuffer, unknownCommand);
                return false;
            }
        }
        break;
        case SDM_COMMAND_CODE::MCTP:
        {
            fcsCallSucceeded = sendMCTP(
               verifierProtocol.getIncomingPayload(),
               payloadFromFcs,
               statusReturnedFromFcs);
        }
        break;
        default:
        {
            Logger::log("Command code not recognized: "
                + std::to_string(verifierProtocol.getCommandCode()));
            verifierProtocol.prepareEmptyResponseMessage(
                responseBuffer, unknownCommand);
            return false;
        }
        break;
    }

    /*
    if fcsCallSucceeded is false
    don't prepare any message, server should disconnect
    - emulates system console behavior
    */
    if (fcsCallSucceeded)
    {
        if (!skipPrepareResponseHeader) {
            verifierProtocol.prepareResponseMessage(
                        payloadFromFcs, responseBuffer, statusReturnedFromFcs);
        } else {
            std::copy(payloadFromFcs.begin(), payloadFromFcs.end(), std::back_inserter(responseBuffer));
        }
    }
    return fcsCallSucceeded;
}

void FcsCommunicationFcsLib::initLibrary()
{
    const char* libFCSLibraryName = "libFCS.so";

#ifdef LIB_FCS_MOCK
    libFCSLibraryName = "libFCSMock.so";
#endif

    assert(libFcsLibrary == (LIBFCS_LIB)(nullptr));
    libFcsLibrary = dlopen(libFCSLibraryName, RTLD_NOW);

    if (libFcsLibrary == (LIBFCS_LIB)(nullptr))
    {
        throw FcsLibraryNotFoundException("Failed to find the FCS library.");
    }

    // Get the APIs
    assert(fcs_get_jtag_idcode == nullptr);
    assert(fcs_get_chip_id == nullptr);
    assert(fcs_attestation_get_certificate == nullptr);
    assert(fcs_mctp_cmd_send == nullptr);
    assert(fcs_get_device_identity == nullptr);
    assert(fcs_qspi_open == nullptr);
    assert(fcs_qspi_close == nullptr);
    assert(fcs_qspi_set_cs == nullptr);
    assert(fcs_qspi_erase == nullptr);
    assert(fcs_qspi_read == nullptr);
    assert(fcs_qspi_write == nullptr);
    assert(libfcs_init == nullptr);
    *(void**)(&fcs_get_jtag_idcode) = dlsym(libFcsLibrary, "fcs_get_jtag_idcode");
    *(void**)(&fcs_get_chip_id) = dlsym(libFcsLibrary, "fcs_get_chip_id");
    *(void**)(&fcs_attestation_get_certificate) = dlsym(libFcsLibrary, "fcs_attestation_get_certificate");
    *(void**)(&fcs_mctp_cmd_send) = dlsym(libFcsLibrary, "fcs_mctp_cmd_send");
    *(void**)(&fcs_get_device_identity) = dlsym(libFcsLibrary, "fcs_get_device_identity");
    *(void**)(&fcs_qspi_open) = dlsym(libFcsLibrary, "fcs_qspi_open");
    *(void**)(&fcs_qspi_close) = dlsym(libFcsLibrary, "fcs_qspi_close");
    *(void**)(&fcs_qspi_set_cs) = dlsym(libFcsLibrary, "fcs_qspi_set_cs");
    *(void**)(&fcs_qspi_erase) = dlsym(libFcsLibrary, "fcs_qspi_erase");
    *(void**)(&fcs_qspi_read) = dlsym(libFcsLibrary, "fcs_qspi_read");
    *(void**)(&fcs_qspi_write) = dlsym(libFcsLibrary, "fcs_qspi_write");
    *(void**)(&libfcs_init) = dlsym(libFcsLibrary, "libfcs_init");
    assert(fcs_get_jtag_idcode);
    assert(fcs_get_chip_id);
    assert(fcs_attestation_get_certificate);
    assert(fcs_mctp_cmd_send);
    assert(fcs_get_device_identity);
    assert(fcs_qspi_open);
    assert(fcs_qspi_close);
    assert(fcs_qspi_set_cs);
    assert(fcs_qspi_erase);
    assert(fcs_qspi_read);
    assert(fcs_qspi_write);
    assert(libfcs_init);

    /** Initialize the FCS library */
    char log_level[10] = "log_dbg";
    int ret = libfcs_init(log_level);
    if (ret != 0) {
        throw FcsLibraryFailedToInitializeException("Failed to initialize FCS library.");
    }
}

bool FcsCommunicationFcsLib::getChipId(
    std::vector<uint8_t>& outBuffer, int32_t& fcsStatus)
{
    altera_fcs_dev data = {};
    fcsStatus = fcs_get_chip_id(
        &data.com_paras.c_chipid.chip_id_lo,
        &data.com_paras.c_chipid.chip_id_hi);
    if (fcsStatus != 0)
    {
        return false;
    }

    outBuffer.resize(sizeof(data.com_paras.c_chipid));

    Utils::encodeToLittleEndianBuffer(
        data.com_paras.c_chipid.chip_id_lo,
        outBuffer);
    Utils::encodeToLittleEndianBuffer(
        data.com_paras.c_chipid.chip_id_hi,
        outBuffer,
        sizeof(data.com_paras.c_chipid.chip_id_lo));
    return true;
}

bool FcsCommunicationFcsLib::getJtagIdCode(
    std::vector<uint8_t>& outBuffer, int32_t& fcsStatus)
{
    altera_fcs_dev data = {};
    fcsStatus = fcs_get_jtag_idcode(&data.com_paras.c_idcode.idcode);
    if (fcsStatus != 0)
    {
        return false;
    }
    outBuffer = Utils::byteBufferFromWordPointer(&data.com_paras.c_idcode.idcode, 1);

    return true;
}

bool FcsCommunicationFcsLib::getAttestationCertificate(
    uint8_t certificateRequest,
    std::vector<uint8_t>& outBuffer,
    int32_t& fcsStatus)
{
    outBuffer.resize(ATTESTATION_CERTIFICATE_RSP_MAX_SZ);
    altera_fcs_dev data = {};
    data.com_paras.c_attestation_certificate.cert = (char*) outBuffer.data();
    data.com_paras.c_attestation_certificate.cert_size = outBuffer.size();
    fcsStatus = fcs_attestation_get_certificate(
                certificateRequest,
                data.com_paras.c_attestation_certificate.cert,
                &data.com_paras.c_attestation_certificate.cert_size);
    if (fcsStatus != 0
        || data.com_paras.c_attestation_certificate.cert_size > ATTESTATION_CERTIFICATE_RSP_MAX_SZ)
    {
        return false;
    }

    outBuffer.resize(data.com_paras.c_attestation_certificate.cert_size);
    std::copy(data.com_paras.c_attestation_certificate.cert,
     data.com_paras.c_attestation_certificate.cert + data.com_paras.c_attestation_certificate.cert_size,
     outBuffer.begin());

    return true;
}

bool FcsCommunicationFcsLib::getDeviceIdentity(std::vector<uint8_t>& outBuffer, int32_t& fcsStatus)
{
    outBuffer.resize(MBOX_SEND_RSP_MAX_SZ);
    altera_fcs_dev data = {};
    data.com_paras.c_device_identity.dev_identity = (char*)outBuffer.data();
    data.com_paras.c_device_identity.dev_identity_length = outBuffer.size();
    fcsStatus = fcs_get_device_identity(
                data.com_paras.c_device_identity.dev_identity,
                &data.com_paras.c_device_identity.dev_identity_length);
    if (fcsStatus != 0)
    {
        return false;
    }
    outBuffer.resize(data.com_paras.c_device_identity.dev_identity_length);
    std::copy(data.com_paras.c_device_identity.dev_identity,
     data.com_paras.c_device_identity.dev_identity + data.com_paras.c_device_identity.dev_identity_length,
     outBuffer.begin());
    return true;
}

bool FcsCommunicationFcsLib::sendMCTP(std::vector<uint8_t> inBuffer, std::vector<uint8_t>& outBuffer, int32_t& fcsStatus)
{
    outBuffer.resize(MBOX_SEND_RSP_MAX_SZ);
    altera_fcs_dev data = {};
    data.com_paras.c_mctp.mctp_resp = (char*)outBuffer.data();
    data.com_paras.c_mctp.resp_len = outBuffer.size();
    fcsStatus = fcs_mctp_cmd_send(
                (char*) inBuffer.data(),
                inBuffer.size(),
                data.com_paras.c_mctp.mctp_resp,
                &data.com_paras.c_mctp.resp_len);
    if (fcsStatus != 0)
    {
        return false;
    }

    outBuffer.resize(data.com_paras.c_mctp.resp_len);
    std::copy(data.com_paras.c_mctp.mctp_resp,
     data.com_paras.c_mctp.mctp_resp + data.com_paras.c_mctp.resp_len,
     outBuffer.begin());
    return true;
}

bool FcsCommunicationFcsLib::qspiOpen(int32_t& fcsStatus)
{
    fcsStatus = fcs_qspi_open();
    if (fcsStatus != 0)
    {
        return false;
    }
    return true;
}

bool FcsCommunicationFcsLib::qspiClose(int32_t& fcsStatus)
{
    fcsStatus = fcs_qspi_close();
    if (fcsStatus != 0)
    {
        return false;
    }
    return true;
}

bool FcsCommunicationFcsLib::qspiErase(std::vector<uint8_t> inBuffer, int32_t& fcsStatus)
{
    std::vector<uint32_t> inBufferU32 = Utils::wordBufferFromByteBuffer(inBuffer);
    assert (inBufferU32.size() == 2);
    uint32_t qspi_addr = inBufferU32[0];
    uint32_t len = inBufferU32[1];
    fcsStatus = fcs_qspi_erase(qspi_addr, len);
    if (fcsStatus != 0)
    {
        return false;
    }
    return true;
}

bool FcsCommunicationFcsLib::qspiSetCS(std::vector<uint8_t> inBuffer, int32_t& fcsStatus)
{
    std::vector<uint32_t> inBufferU32 = Utils::wordBufferFromByteBuffer(inBuffer);
    assert (inBufferU32.size() == 1);
    uint32_t cs = inBufferU32[0];
    fcsStatus = fcs_qspi_set_cs(cs);
    if (fcsStatus != 0)
    {
        return false;
    }
    return true;
}

bool FcsCommunicationFcsLib::qspiRead(std::vector<uint8_t> inBuffer, std::vector<uint8_t>& outBuffer, int32_t& fcsStatus)
{
    altera_fcs_dev data = {};
    std::vector<uint32_t> inBufferU32 = Utils::wordBufferFromByteBuffer(inBuffer);
    assert (inBufferU32.size() == 2);
    uint32_t qspi_addr = inBufferU32[0];
    uint32_t len = inBufferU32[1];
    outBuffer.resize(len * WORD_SIZE);
    data.com_paras.c_qspi_read.buffer = (char*)outBuffer.data();
    fcsStatus = fcs_qspi_read(qspi_addr, data.com_paras.c_qspi_read.buffer, len);
    if (fcsStatus != 0)
    {
        return false;
    }

    std::copy(data.com_paras.c_qspi_read.buffer,
     data.com_paras.c_qspi_read.buffer + (len * WORD_SIZE),
     outBuffer.begin());
    return true;
}

bool FcsCommunicationFcsLib::qspiWrite(std::vector<uint8_t> inBuffer, int32_t& fcsStatus)
{
    std::vector<uint32_t> inBufferU32 = Utils::wordBufferFromByteBuffer(inBuffer);
    assert (inBufferU32.size() > 2);
    uint32_t qspi_addr = inBufferU32[0];
    uint32_t len = inBufferU32[1];
    fcsStatus = fcs_qspi_write(qspi_addr, (char*) (inBuffer.data() + 8), len);
    if (fcsStatus != 0)
    {
        return false;
    }
    return true;
}
