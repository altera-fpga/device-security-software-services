#!/bin/bash

#
# This project is licensed as below.
#
# ***************************************************************************
#
# Copyright 2020-2026 Altera Corporation. All Rights Reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
# OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# ***************************************************************************
#

readonly SCRIPT_DIR=$(cd `dirname "${BASH_SOURCE[0]}"` && pwd)

BKP_PROGRAMMER_PATH=${SCRIPT_DIR}
VALGRIND_OUTPUT_FILE=${BKP_PROGRAMMER_PATH}/valgrind_output_test

echo "Starting testing memory leaks..."

mkdir -p ${VALGRIND_OUTPUT_FILE}

echo "Building library..."

bash ${SCRIPT_DIR}/build.sh -c -b --valgrind

echo "Testing memory leaks in tests"
for line in $(find ${SCRIPT_DIR}/build/Release/src/ -maxdepth 3 -perm -111 -type f | grep "_test$"); do
     base_name=$(basename ${line})
     echo "Testing suite: $base_name"
     valgrind --leak-check=full --xml=yes --xml-file=${VALGRIND_OUTPUT_FILE}/${base_name}.%p.result ${line}
done

exit 0
