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

#ifndef PROGRAMMER_GET_NEXT_H
#define PROGRAMMER_GET_NEXT_H

#include "network/network_message.h"

class GetNextRequest: public NetworkRequest
{
public:
    BkpsContext context;
    std::string cfgId;
};

class GetNextResponse: public NetworkResponse
{
public:
    BkpsContext context;
};

class GetNextMessage: public NetworkMessage
{
private:
    GetNextRequest request;
    GetNextResponse response;
public:
    GetNextMessage(std::string cfgId)
    {
        request.cfgId = cfgId;
    }
    std::string getEndpoint() override { return "/prov/v1/get_next"; }
    NetworkRequest& getRequest() override { return request; }
    NetworkResponse& getResponse() override { return response; }
    std::string getRequestJson() override
    {
        boost::json::object jsonObject = getRequestJsonCommon();
        jsonObject.emplace(fields::cfg_id, request.cfgId);
        jsonObject.emplace(fields::context, boost::json::object({{fields::context_value, request.context.value}}));
        return boost::json::serialize(jsonObject);
    };
    void parseFromResponseJson(std::string jsonString) override
    {
        boost::json::value jsonValue = boost::json::parse(jsonString);
        parseFromResponseJsonCommon(jsonValue);
        response.context.value = jsonValue.at(fields::context).at(fields::context_value).as_string();

        // received context needs to be returned to BKPS with next request
        request.context = response.context;
    };
};


#endif //PROGRAMMER_GET_NEXT_H
