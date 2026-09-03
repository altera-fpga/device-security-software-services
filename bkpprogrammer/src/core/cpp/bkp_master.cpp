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

#include "bkp_master.h"

Config BkpMaster::getConfigFromQuartusContext() const
{
    Config conf;

    conf.caCertFilePath = qc->get_config(CFG_TLS_CA_CERT);
    LOG(L_DEBUG, logMessages::cert::load_root + conf.caCertFilePath);
    conf.clientCertFilePath = qc->get_config(CFG_TLS_PROG_CERT);
    LOG(L_DEBUG, logMessages::cert::load_client + conf.clientCertFilePath);
    conf.clientKeyFilePath = qc->get_config(CFG_TLS_PROG_KEY);
    LOG(L_DEBUG, logMessages::cert::load_key + conf.clientKeyFilePath);
    conf.clientKeyPassword = qc->get_config(CFG_TLS_PROG_KEY_PASS);
    LOG(L_DEBUG, logMessages::password::looking_for_password + "device config.");

    conf.bkpsAddress = qc->get_config(CFG_BKPSVC_IP);
    conf.bkpsPort = qc->get_config(CFG_BKPSVC_PORT);

    conf.proxyAddressAndPort = qc->get_config(CFG_PROXY_ADDRESS);
    if (conf.proxyAddressAndPort.empty())
    {
        LOG(L_DEBUG, logMessages::proxy::no_proxy);
        return conf;
    }
    LOG(L_INFO, logMessages::proxy::set_to + conf.proxyAddressAndPort);

    conf.proxyUsername = qc->get_config(CFG_PROXY_USER);
    if (conf.proxyUsername.empty()) {
        LOG(L_DEBUG, logMessages::proxy::no_proxy_auth);
        return conf;
    }
    conf.proxyPassword = qc->get_config(CFG_PROXY_PASS);
    return conf;
}

Status_t BkpMaster::provision() const
{
    operationTypeString = "Provisioning";
    GetNextMessage initialMessage(getCfgId());
    return perform_message_exchange(initialMessage);
}

Status_t BkpMaster::prefetch() const
{
    operationTypeString = "Prefetching";
    PrefetchNextMessage initialMessage;
    return perform_message_exchange(initialMessage);
}

Status_t BkpMaster::pufActivate(PufType_t pufType) const
{
    operationTypeString = "PUF activate";
    PufActivateNextMessage initialMessage(pufType);
    return perform_message_exchange(initialMessage);
}

Status_t BkpMaster::setAuthority(PufType_t pufType, uint8_t slotId, bool force_enrollment) const
{
    operationTypeString = "Set authority";
    SetAuthorityNextMessage initialMessage(pufType, slotId, force_enrollment);
    return perform_message_exchange(initialMessage);
}

Status_t BkpMaster::perform_message_exchange(NetworkMessage &networkMessage) const {
    try {
        try {
            networkMessage.getRequest().apiVersion = CURRENT_API_VERSION;
            networkMessage.getRequest().supportedCommands = getSupportedCommands();
            Config conf = getConfigFromQuartusContext();
            network->init(conf, networkMessage.getEndpoint());

            for (int i = 0; i < MAX_ITERATION_COUNT; i++) {
                std::string receivedData;
                std::string jsonPayload = networkMessage.getRequestJson();
                LOG(L_DEBUG, "Prepared payload: " + jsonPayload);
                network->perform(jsonPayload, receivedData);
                networkMessage.getRequest().jtagResponses.clear();
                LOG(L_DEBUG, "Received data from BKPS: " + receivedData);
                try
                {
                    networkMessage.parseFromResponseJson(receivedData);
                }
                catch (const std::exception &ex)
                {
                    throw BkpJsonParsingException(ex.what());
                }
                std::vector<Command> &jtagCommands = networkMessage.getResponse().jtagCommands;
                if (!jtagCommands.empty()) {
                    logReceivedBkps();
                    networkMessage.getRequest().jtagResponses = send_commands_to_quartus(jtagCommands);
                }

                if (isStatusDone(networkMessage)) {
                    return reportSuccess();
                }

                if (!isStatusContinue(networkMessage)) {
                    return reportError();
                }
            }

            return reportExceededMaxIterationCount();
        }
        catch (const BkpException&)
        {
            throw;
        }
        catch (const std::exception &e)
        {
            throw BkpServiceUnavailableException(std::string(e.what()));
        }
    }
    catch (const std::exception &ex)
    {
        return reportError(ex);
    }
    catch(...)
    {
        return reportError();
    }
}

std::string BkpMaster::getCfgId() const {
    return qc->get_config(CFG_ID);
}

uint32_t BkpMaster::getSupportedCommands() const {
    return qc->get_supported_commands();
}

bool BkpMaster::isStatusDone(NetworkMessage &msg) const {
    return msg.getResponse().status == communication_status::comm_done;
}

bool BkpMaster::isStatusContinue(NetworkMessage &msg) const {
    return msg.getResponse().status == communication_status::comm_continue;
}

std::vector<Response> BkpMaster::send_commands_to_quartus(std::vector<Command> jtagCommands) const
{
    std::vector<Response> quartusResponses;
    for (const auto &command : jtagCommands) {
        // :TODO - pass bkpsResponse.api_version to jtag->exchange_jtag_cmd
        std::string quartusResponse;
        Status_t quartusStatus = jtag->exchange_jtag_cmd(command, quartusResponse);
        Response resp = { quartusResponse, quartusStatus };
        quartusResponses.emplace_back(resp);
    }
    logReceivedQuartus();
    return quartusResponses;
}

void BkpMaster::logReceivedBkps() const
{
    LOG(L_INFO, provisioning_stage::received_from_bkps);
}

void BkpMaster::logReceivedQuartus() const
{
    LOG(L_INFO, provisioning_stage::received_from_quartus);
}


Status_t BkpMaster::reportSuccess() const {
    LOG(L_INFO, operationTypeString + operation_status::completed);
    return ST_OK;
}

Status_t BkpMaster::reportError() const {
    LOG(L_ERROR, operationTypeString + operation_status::failed);
    return ST_GENERIC_ERROR;
}

Status_t BkpMaster::reportError(const std::exception &ex) const {
    LOG(L_ERROR, std::string(ex.what()));
    LOG(L_ERROR, operationTypeString + operation_status::failed);
    return ST_GENERIC_ERROR;
}

Status_t BkpMaster::reportExceededMaxIterationCount() const {
    LOG(L_ERROR, "Exceeded maximum requests counter.");
    LOG(L_ERROR, operationTypeString + operation_status::failed);
    return ST_GENERIC_ERROR;
}
