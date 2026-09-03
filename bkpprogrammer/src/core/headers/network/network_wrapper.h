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

#ifndef PROGRAMMER_NETWORKWRAPPER_H
#define PROGRAMMER_NETWORKWRAPPER_H

#include <cstdlib>
#include <cstring>
#include <cstddef>
#include <vector>
#include <string>
#include <boost/algorithm/string.hpp>
#include <curl/curl.h>

#include "logger.h"
#include "network_config.h"

//Interface
class NetworkWrapper
{
protected:
    NetworkWrapper() = default;

public:
    virtual ~NetworkWrapper() = default;
    virtual void init(Config config, std::string endpoint) = 0;
    virtual void perform(const std::string &postData, std::string &receivedData) = 0;
};

class CurlWrapper: public NetworkWrapper
{
private:
    template <typename T>
    void setCurlOptionWithErrorHandling(CURL *handle, CURLoption option, T parameter);
    const long httpCodeOk = 200;
    const static inline std::string acceptedCiphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256";
    const static inline std::string transactionIdHeaderField = "X-Request-TransactionId";
    const static inline std::vector<std::string> additionalHeaders =
    {
        "Accept: application/json",
        "Content-Type: application/json",
        "charset: utf-8"
    };
    const static size_t initialBufferSize = 5000;
    const static size_t connectTimeoutInSeconds = 20;
    const static size_t timeoutInSeconds = 30;
    std::shared_ptr<Logger> logger;
    std::shared_ptr<TransactionIdManager> txIdMgr;
    std::string url;
    CURL *curlHandle = nullptr;
    std::string dataBuffer;

public:
    std::string transactionId;
    static size_t writeMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
    static size_t findTransactionIdInHeaders(void *contents, size_t size, size_t nmemb, void *userp);
    static int debugCallback(CURL *handle, curl_infotype type, char *data, size_t size, void *clientp);
    curl_slist* getOutgoingHeaders();

    explicit CurlWrapper(std::shared_ptr<Logger> logger_, std::shared_ptr<TransactionIdManager> txIdMgr_);
    CurlWrapper(const CurlWrapper &L) = delete;
    CurlWrapper &operator=(const CurlWrapper &L) = delete;
    void init(Config config, std::string endpoint) override;
    void perform(const std::string &postData, std::string &receivedData) override;
    ~CurlWrapper();
};

#endif //PROGRAMMER_NETWORKWRAPPER_H
