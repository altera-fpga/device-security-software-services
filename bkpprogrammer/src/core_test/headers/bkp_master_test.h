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

#ifndef BKP_MASTER_TEST_H
#define BKP_MASTER_TEST_H

#include <gmock/gmock.h>

#include <utility>

#include "bkp_master.h"
#include "mocks/mocked_logger.h"
#include "mocks/mocked_transaction_id_manager.h"
#include "mocks/mocked_quartus.h"


using testing::_;
using testing::Return;
using testing::Throw;
using testing::Matcher;

class MockNetwork : public NetworkWrapper {
public:
    MOCK_METHOD(void, init, (Config config, std::string endpoint), (override));
    MOCK_METHOD(void, perform, (const std::string &postData, std::string &receivedData), (override));
};

class MockJtagHelper : public JtagHelper {
public:
    MOCK_METHOD(Status_t, exchange_jtag_cmd, (const Command &command, std::string &outResponse), (override));
};

class MockException : public std::exception {
protected:
    std::string msg;

public:
    explicit MockException(std::string msg_) : msg(std::move(msg_)) {};

    const char *what() const noexcept override {
        return msg.c_str();
    }
};

class MockBkpUnknownException : public BkpException {
public:
    std::error_code error_code = (BkpErrc)100000;

    explicit MockBkpUnknownException(std::string errorMsg) {
        msg = str_utils::concat_strings( {gen_error_code_str(error_code), std::move(errorMsg)} );
    }
};

class BkpMasterTest : public ::testing::Test
{
protected:
    void mockEmptyNetworkCalls();
    void mockNetworkCalls(std::string jsonFromBkps);
    void mockLoggerInitializationMessages();
    void mockLoggerSendingData(int times = 1);
    void mockLoggerReceivedData(int times = 1);
    void mockLoggerCalls();
    void mockNetworkInitProvisioning();
    void mockNetworkInitPrefetch();
    void mockNetworkDone();
    void mockNetworkContinueThenDone();
    void mockNetworkContinueWithEmptyJtagCmd();
    void mockNetworkContinueManyTimes(int times);
    void mockNetworkThrowHttpException();
    void mockNetwork2JtagCommandsAndDone();
    void mockJtagCalls(size_t numberOfCommands);
    void mockLoggerPrefetchingSuccess();
    void mockLoggerProvisioningSuccess();
    void mockLoggerPrefetchingFail();
    void mockLoggerProvisioningFail();
    void mockLoggerFailWithMessage(const std::string &message);
    void mockLoggerFailWithMessage(const std::string &message, const std::string &error_msg);

public:
    std::shared_ptr<MockLogger> mockLoggerPtr;
    std::shared_ptr<MockTransactionIdManager> mockTxIdMgrPtr;
    std::shared_ptr<MockNetwork> mockNetworkPtr;
    std::shared_ptr<MockJtagHelper> mockJtagPtr;
    MockQuartusContext qc;

    std::string testMessage = "test";
    std::string unknownError = "Unknown error";

    BkpMasterTest() :
            mockLoggerPtr(std::make_shared<MockLogger>()),
            mockTxIdMgrPtr(std::make_shared<MockTransactionIdManager>()),
            mockNetworkPtr(std::make_shared<MockNetwork>()),
            mockJtagPtr(std::make_shared<MockJtagHelper>()) {

        EXPECT_CALL(qc, get_config).WillRepeatedly(Return("1000"));
        EXPECT_CALL(qc, get_supported_commands).WillRepeatedly(Return(1));
    };
};

#endif //BKP_MASTER_TEST_H
