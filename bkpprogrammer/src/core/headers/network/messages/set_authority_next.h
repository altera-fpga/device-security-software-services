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

#ifndef PROGRAMMER_SET_AUTHORITY_NEXT_H
#define PROGRAMMER_SET_AUTHORITY_NEXT_H

#include "network/network_message.h"

class SetAuthorityNextRequest: public NetworkRequest
{
public:
    BkpsContext context;
    uint32_t pufType;
    uint8_t slotId;
    bool forceEnrollment;
};

class SetAuthorityNextResponse: public NetworkResponse
{
public:
    BkpsContext context;
};

class SetAuthorityNextMessage: public NetworkMessage
{
private:
    SetAuthorityNextRequest request;
    SetAuthorityNextResponse response;
public:
    SetAuthorityNextMessage(uint32_t pufType, uint8_t slotId, bool forceEnrollment)
    {
        request.pufType = pufType;
        request.slotId = slotId;
        request.forceEnrollment = forceEnrollment;
    }
    std::string getEndpoint() override { return "/prov/v1/set_authority"; }
    NetworkRequest& getRequest() override { return request; }
    NetworkResponse& getResponse() override { return response; }
    std::string getRequestJson() override
    {
        boost::json::object jsonObject = getRequestJsonCommon();
        jsonObject.emplace(fields::puf_type, request.pufType);
        jsonObject.emplace(fields::slot_id, request.slotId);
        jsonObject.emplace(fields::force_enrollment, request.forceEnrollment);
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

#endif //PROGRAMMER_SET_AUTHORITY_NEXT_H
