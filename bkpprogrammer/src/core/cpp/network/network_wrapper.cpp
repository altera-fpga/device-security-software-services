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

#include <curl/curl.h>
#include <regex>

#include "network/network_wrapper.h"
#include "utils/bkp_exception.h"

// This function is designed to be called by libCurl for each incoming chunk of data (usually 1).
// It appends all data to supplied string userp
size_t CurlWrapper::writeMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) // userp is std::string*
{
    size_t realSize = size * nmemb;
    std::string *str = static_cast<std::string*>(userp);
    str->append(static_cast<char*>(contents), realSize);
    return realSize;
}

// This function is designed to be called by libCurl for each incoming header.
// If currently processed header is TransactionId, its value is copied to userp
size_t CurlWrapper::findTransactionIdInHeaders(void *contents, size_t size, size_t nmemb, void *userp) // userp is std::string*
{
    size_t realSize = size * nmemb;
    std::string incomingHeader(static_cast<char*>(contents), realSize);
    std::regex re(transactionIdHeaderField + ": (\\S+)");
    std::smatch matches;
    if (std::regex_search(incomingHeader, matches, re))
    {
        std::string *str = static_cast<std::string*>(userp);
        *str = matches[1].str();
    }
    return realSize;
}

int CurlWrapper::debugCallback(CURL *handle, curl_infotype type, char *data, size_t size, void *clientp)
{
    (void)handle; /* prevent compiler warning */
    std::string line(data, data + size);
    Logger *logger_ptr = static_cast<Logger*>(clientp);
    switch(type)
    {
        case CURLINFO_TEXT:
        case CURLINFO_HEADER_IN:
        case CURLINFO_HEADER_OUT:
        case CURLINFO_DATA_IN:
        case CURLINFO_DATA_OUT:
            logger_ptr->log(L_DEBUG, "[CURL] " + line);
            break;
        default:
            break;
    }
    return 0;
}

template <typename T>
void CurlWrapper::setCurlOptionWithErrorHandling(CURL *handle, CURLoption option, T parameter)
{
    CURLcode returnCode = curl_easy_setopt(handle, option, parameter);
    if (returnCode != CURLE_OK)
    {
        throw BkpInternalException(
            "Failed to set CURL option " + std::to_string(option) + ". Return code: " + std::to_string(returnCode));
    }
}

CurlWrapper::CurlWrapper(std::shared_ptr<Logger> logger_, std::shared_ptr<TransactionIdManager> txIdMgr_) :
    logger(std::move(logger_)),
    txIdMgr(std::move(txIdMgr_))
{
    //preallocate memory for data to avoid costly reallocations during append() calls
    dataBuffer.reserve(initialBufferSize);

    curlHandle = curl_easy_init();
    if (!curlHandle)
    {
        throw BkpInternalException("Failed to initialize curl.");
    }

    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_WRITEFUNCTION, writeMemoryCallback);
    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_WRITEDATA, (void *)&dataBuffer);

    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_HEADERFUNCTION, findTransactionIdInHeaders);
    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_HEADERDATA, (void *)&transactionId);

    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_SSL_CIPHER_LIST, acceptedCiphers.c_str());

    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_FOLLOWLOCATION, true);
    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_TIMEOUT, timeoutInSeconds);
    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_CONNECTTIMEOUT, connectTimeoutInSeconds);
    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_NOPROXY, ""); // ignore no_proxy environment variable
    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_DEBUGFUNCTION, debugCallback);
    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_DEBUGDATA, (void *)logger.get());
    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_VERBOSE, true);
};

void CurlWrapper::init(Config config, std::string endpoint)
{
    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_CAINFO, config.caCertFilePath.c_str());
    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_SSLCERT, config.clientCertFilePath.c_str());
    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_SSLKEY, config.clientKeyFilePath.c_str());
    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_KEYPASSWD, config.clientKeyPassword.c_str());
    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_PROXY, config.proxyAddressAndPort.c_str());
    if (!config.proxyUsername.empty())
    {
        setCurlOptionWithErrorHandling(curlHandle, CURLOPT_PROXYUSERNAME, config.proxyUsername.c_str());
    }
    if (!config.proxyPassword.empty())
    {
        setCurlOptionWithErrorHandling(curlHandle, CURLOPT_PROXYPASSWORD, config.proxyPassword.c_str());
    }

    url = "https://" + config.bkpsAddress + ":" + config.bkpsPort + endpoint;
}

curl_slist* CurlWrapper::getOutgoingHeaders()
{
    curl_slist *outHeaders = nullptr;

    std::vector<std::string> headers = additionalHeaders;
    headers.push_back(transactionIdHeaderField + ": " + transactionId);

    for (const std::string &header : headers)
    {
        outHeaders = curl_slist_append(outHeaders, header.c_str());
        if (!outHeaders)
        {
            throw BkpInternalException("curl_slist_append failed.");
        }
    }
    return outHeaders;
}

void CurlWrapper::perform(const std::string &postData, std::string &receivedData)
{
    LOG(L_INFO, "Resolved URL: " + url);
    dataBuffer.clear();

    curl_slist *outHeaders = getOutgoingHeaders();
    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_HTTPHEADER, outHeaders);

    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_URL, url.c_str());
    setCurlOptionWithErrorHandling(curlHandle, CURLOPT_POSTFIELDS, postData.c_str());

    CURLcode res = curl_easy_perform(curlHandle);

    curl_slist_free_all(outHeaders);
    receivedData = dataBuffer;
    if(res != CURLE_OK)
    {
        throw BkpHttpException(std::string(curl_easy_strerror(res)));
    }
    if (!transactionId.empty())
    {
        txIdMgr->set_transaction_id(transactionId);
    }

    long http_code = 0;
    curl_easy_getinfo(curlHandle, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != httpCodeOk)
    {
        throw BkpServiceResponseException(receivedData);
    }
}

CurlWrapper::~CurlWrapper()
{
    curl_easy_cleanup(curlHandle);
    curl_global_cleanup();
}
