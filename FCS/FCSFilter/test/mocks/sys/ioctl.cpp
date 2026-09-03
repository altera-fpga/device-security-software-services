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

#include "ioctl.h"
#include "fcntl.h"
#include "Logger.h"

#include <fstream>
#include <vector>

#include "FcsSimulator.h"

#ifdef SPDM_SIM
#include "spdmSimulator.h"
#endif

#define CHIPID_LOW 0x18ACEC5A
#define CHIPID_HIGH 0x0782C6CC

const uint32_t IDCODE = 0x6341D0DD;

int ioctl(int fileDescriptor, unsigned long int commandCode, altera_fcs_dev_ioctl *data) {
    Logger::log("ioctl() mock called", Debug);
    if (data == nullptr) {
        errno = EFAULT;
        return -1;
    }
    if (fileDescriptor != MOCK_FILE_DESCRIPTOR) {
        errno = EBADF;
        return -1;
    }
    switch (commandCode) {
        case (ALTERA_FCS_DEV_CHIP_ID_CMD): {
            data->com_paras.c_id.chip_id_high = CHIPID_HIGH;
            data->com_paras.c_id.chip_id_low = CHIPID_LOW;
            data->status = 0;
        }
        break;
        case (ALTERA_FCS_DEV_PSGSIGMA_TEARDOWN_CMD): {
            if (data->com_paras.tdown.sid != FcsSimulator::expectedSessionId) {
                data->status = -1;
            } else {
                data->status = 0;
            }
        }
        break;
        case (ALTERA_FCS_DEV_ATTESTATION_SUBKEY_CMD): {
            if (data->com_paras.subkey.rsp_data_sz < ATTESTATION_SUBKEY_RSP_MAX_SZ) {
                errno = EINVAL;
                return -1;
            }
            if (data->com_paras.subkey.cmd_data_sz != FcsSimulator::expectedCreateSubkeyCommandLength) {
                data->status = -1;
            } else {
                std::vector <uint8_t> buffer(ATTESTATION_SUBKEY_RSP_MAX_SZ, 0x7E); //0111 1110
                std::copy(buffer.begin(), buffer.end(), data->com_paras.subkey.rsp_data);
                data->com_paras.subkey.rsp_data_sz = buffer.size();
                data->status = 0;
            }
        }
        break;
        case (ALTERA_FCS_DEV_ATTESTATION_MEASUREMENT_CMD): {
            if (data->com_paras.measurement.rsp_data_sz < ATTESTATION_MEASUREMENT_RSP_MAX_SZ) {
                errno = EINVAL;
                return -1;
            }
            if (data->com_paras.measurement.cmd_data_sz != FcsSimulator::expectedGetMeasurementCommandLength) {
                data->status = -1;
            }
            std::vector <uint8_t> buffer(FcsSimulator::expectedGetMeasurementResponseLength, 0x7E); //0111 1110
            std::copy(buffer.begin(), buffer.end(), data->com_paras.subkey.rsp_data);
            data->com_paras.measurement.rsp_data_sz = buffer.size();
            data->status = 0;
        }
        break;
#ifdef SPDM_SIM
        case (ALTERA_FCS_DEV_ATTESTATION_GET_CERTIFICATE): {
            std::vector<uint8_t> outputBuffer;
            int status = SpdmSimulator::sendGetAttestationCommand(data->com_paras.certificate.c_request, outputBuffer);
            Logger::logWithReturnCode("SpdmSimulator::sendGetAttestationCommand called", status, Debug);
            std::copy(outputBuffer.begin(), outputBuffer.end(), static_cast<char*>(data->com_paras.certificate.rsp_data));
            data->com_paras.certificate.rsp_data_sz = outputBuffer.size();
            data->status = 0;
        }
        break;
        case (ALTERA_FCS_DEV_MBOX_SEND): {
            std::vector<uint8_t> inputBuffer;
            uint8_t* dataPtr = static_cast<uint8_t*>(data->com_paras.mbox_send_cmd.cmd_data);
            inputBuffer.assign(dataPtr, dataPtr + data->com_paras.mbox_send_cmd.cmd_data_sz);
            std::vector<uint8_t> outputBuffer;

            switch (data->com_paras.mbox_send_cmd.mbox_cmd) {
                case (GET_IDCODE): {
                    Logger::log("SpdmSimulator::getIdCode called", Debug);
                    memcpy(data->com_paras.mbox_send_cmd.rsp_data, &IDCODE, sizeof(IDCODE));
                    data->com_paras.mbox_send_cmd.rsp_data_sz = sizeof(IDCODE);
                    data->status = 0;
                }
                break;
                default: {
                    Logger::log("SpdmSimulator::sendCommand called", Debug);
                    int status = SpdmSimulator::sendCommand(data->com_paras.mbox_send_cmd.mbox_cmd, inputBuffer, outputBuffer);
                    Logger::logWithReturnCode("SpdmSimulator::sendCommand", status, Debug);
                    std::copy(outputBuffer.begin(), outputBuffer.end(), static_cast<uint8_t*>(data->com_paras.mbox_send_cmd.rsp_data));
                    data->com_paras.mbox_send_cmd.rsp_data_sz = outputBuffer.size();
                    data->status = 0;
                }
                break;
            }
        }
        break;
#else
        case (ALTERA_FCS_DEV_ATTESTATION_GET_CERTIFICATE): {
            if (data->com_paras.certificate.rsp_data_sz < ATTESTATION_CERTIFICATE_RSP_MAX_SZ) {
                errno = EINVAL;
                return -1;
            }
            if (data->com_paras.certificate.c_request != (int) FcsSimulator::expectedCertificateRequest) {
                data->status = -1;
            }
            std::vector <uint8_t> buffer(FcsSimulator::expectedGetAttCertResponseLength, 0x7E); //0111 1110
            std::copy(buffer.begin(), buffer.end(), data->com_paras.certificate.rsp_data);
            data->com_paras.certificate.rsp_data_sz = buffer.size();
            data->status = 0;
        }
        break;
#endif
        default: {
            errno = EINVAL;
            return -1;
        }
        break;
    }
    return 0;
}
