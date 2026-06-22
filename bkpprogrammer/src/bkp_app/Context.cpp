/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2025 Altera Corporation. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * **************************************************************************
 */

#include "utils/bkp_exception.h"

#include "Context.h"
#include "Logger.h"
#include "utils.h"
#include "MessageHandler.h"

#include <fstream>
#include <stdexcept>
#include <vector>

void Context::readConfig(std::string fileName)
{
    std::ifstream configFile(fileName);
    if (!configFile)
    {
        log(L_ERROR, "Cannot open config file");
        throw std::runtime_error("Cannot open config file");
    }

    po::options_description desc("Allowed options");
    desc.add_options()
        (CFG_ID.c_str(), po::value<std::string>())
        (CFG_BKPSVC_IP.c_str(), po::value<std::string>())
        (CFG_BKPSVC_PORT.c_str(), po::value<std::string>())
        (CFG_PROXY_ADDRESS.c_str(), po::value<std::string>())
        (CFG_PROXY_USER.c_str(), po::value<std::string>())
        (CFG_PROXY_PASS.c_str(), po::value<std::string>())
        (CFG_TLS_CA_CERT.c_str(), po::value<std::string>())
        (CFG_TLS_PROG_CERT.c_str(), po::value<std::string>())
        (CFG_TLS_PROG_KEY.c_str(), po::value<std::string>())
        (CFG_TLS_PROG_KEY_PASS.c_str(), po::value<std::string>());

    try
    {
        po::store(parse_config_file(configFile, desc), parsedConfig);
        po::notify(parsedConfig);
    }
    catch (boost::program_options::error &e)
    {
        Logger::log("Incorrect config file: " + std::string(e.what()), Fatal);
        exit(1);
    }
}

unsigned int Context::get_supported_commands()
{
    return
        (1 << Message_t::SEND_PACKET) +
        (1 << Message_t::PUSH_WRAPPED_KEY) +
        (1 << Message_t::PUSH_WRAPPED_KEY_USER_IID) +
        (1 << Message_t::PUSH_WRAPPED_KEY_UDS_IID) +
        (1 << Message_t::PUSH_HELPER_DATA_UDS_IID) +
        (1 << Message_t::PUSH_HELPER_DATA_UDS_INTEL);
}

void Context::log(LogLevel_t level, const std::string& msg)
{
    LogLevel convertedLevel = Info;
    switch (level)
    {
        case L_DEBUG:
            convertedLevel = Debug;
            break;
        case L_INFO:
            convertedLevel = Info;
            break;
        case L_WARNING:
            convertedLevel = Warning;
            break;
        case L_ERROR:
            convertedLevel = Error;
            break;
    }
    Logger::log(msg, convertedLevel);
}

void Context::writeWkeyToFile(std::vector<BYTE> wkeyData)
{
    std::ofstream file (wkeyFilename, std::ofstream::out | std::ofstream::binary);
    if (!file.good())
    {
        throw BkpInternalException("Failed to open file for write: " + wkeyFilename);
    }
    file.write(reinterpret_cast<char*>(wkeyData.data()), wkeyData.size());
    file.close();
}

bool Context::writeWkeyToFlash(std::vector<BYTE> wkeyData, PufType_t pufType)
{
    Logger::log("Writing AES wrapped key to flash...", Debug);
    PufHandler pufHandler;
    return pufHandler.writeWkeyToFlash(std::move(wkeyData), pufType);
}

bool Context::writePufHelpDataToFlash(std::vector<BYTE> pufHelpData, PufType_t pufType)
{
    Logger::log("Writing PUF help data to flash...", Debug);
    PufHandler pufHandler;
    return pufHandler.writePufHelpDataToFlash(std::move(pufHelpData), pufType);
}

Status_t Context::send_message(Message_t messageType,
                               const DWORD *inBuf, size_t inBufSize,
                               DWORD **outBuf, size_t &outBufSize)
{
    bool status = true;
    std::vector <BYTE> messageVector = Utils::byteBufferFromWordPointer(static_cast<const DWORD *>(inBuf),
                                                                           inBufSize);
    std::vector <BYTE> responseVector;
    switch (messageType)
    {
        case Message_t::SEND_PACKET:
            handleIncomingMessage(messageVector, responseVector);
            break;
        case Message_t::PUSH_WRAPPED_KEY:
            writeWkeyToFile(messageVector);
            break;
        case Message_t::PUSH_WRAPPED_KEY_USER_IID:
            status = writeWkeyToFlash(messageVector, USER_IID);
            if (status && shouldSaveWkeyToMachine)
            {
                writeWkeyToFile(messageVector);
            }
            break;
        case Message_t::PUSH_WRAPPED_KEY_UDS_IID:
            status = writeWkeyToFlash(messageVector, UDS_IID);
            if (status && shouldSaveWkeyToMachine)
            {
                writeWkeyToFile(messageVector);
            }
            break;
        case Message_t::PUSH_HELPER_DATA_UDS_IID:
            status = writePufHelpDataToFlash(messageVector, UDS_IID);
            break;
        case Message_t::PUSH_HELPER_DATA_UDS_INTEL:
            status = writePufHelpDataToFlash(messageVector, UDS_INTEL);
            break;
        default:
            return ST_GENERIC_ERROR;
    }
    if (!status)
    {
        return ST_GENERIC_ERROR;
    }
    Utils::writeToWordPointerFromByteBuffer(responseVector, static_cast<DWORD **>(outBuf), outBufSize);
    return ST_OK;
}

std::string Context::get_config(const std::string& key)
{
    if (!parsedConfig.count(key))
    {
        return std::string("");
    }
    return parsedConfig[key].as<std::string>();
}
