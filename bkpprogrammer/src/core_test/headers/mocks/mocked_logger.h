/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2023 Intel Corporation. All Rights Reserved.
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

#ifndef MOCK_LOGGER_H
#define MOCK_LOGGER_H

#include <gmock/gmock.h>

#include "logger.h"

#ifndef GTEST_MATCH_LIST_ELEM
#define GTEST_MATCH_LIST_ELEM(x) \
    ::testing::Matcher<std::initializer_list<std::string>>(::testing::Contains(::testing::HasSubstr((x))))
#endif //GTEST_MATCH_LIST_ELEM

#ifndef GTEST_MATCH_SUBSTR
#define GTEST_MATCH_SUBSTR(x) \
    ::testing::Matcher<std::string>(::testing::HasSubstr((x)))
#endif //GTEST_MATCH_SUBSTR

#ifndef GTEST_MATCH_SUBSTR2
#define GTEST_MATCH_SUBSTR2(x, y) \
    ::testing::Matcher<std::string>(::testing::AllOf(::testing::HasSubstr((x)), ::testing::HasSubstr((y))))
#endif //GTEST_MATCH_SUBSTR2

class MockLogger : public Logger {
public:
    MOCK_METHOD(void, log,
            (LogLevel_t level, std::string message), (override, const));
};

#endif //MOCK_LOGGER_H
