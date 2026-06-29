/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2026 Altera Corporation. All Rights Reserved.
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

package com.intel.bkp.bkps.utils;

import com.intel.bkp.core.utils.ProfileConstants;
import liquibase.exception.LiquibaseException;
import liquibase.integration.spring.SpringLiquibase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.core.task.TaskExecutor;
import org.springframework.util.StopWatch;

import java.sql.Connection;
import java.sql.SQLException;

public class AsyncSpringLiquibase extends SpringLiquibase {

    private static final String STARTING_ASYNC_MESSAGE =
        "Starting Liquibase asynchronously, your database might not be ready at startup!";
    private static final String STARTING_SYNC_MESSAGE = "Starting Liquibase synchronously";
    private static final String STARTED_MESSAGE = "Liquibase has updated your database in {} ms";
    private static final String EXCEPTION_MESSAGE = "Liquibase could not start correctly, "
        + "your database is NOT ready: {}";

    private static final long SLOWNESS_THRESHOLD = 5; // seconds
    private static final String SLOWNESS_MESSAGE = "Warning, Liquibase took more than {} seconds to start up!";

    // named "logger" because there is already a field called "log" in "SpringLiquibase"
    private final Logger logger = LoggerFactory.getLogger(AsyncSpringLiquibase.class);

    private final TaskExecutor taskExecutor;

    private final Environment env;

    public AsyncSpringLiquibase(@Qualifier("taskExecutor") TaskExecutor taskExecutor, Environment env) {
        this.taskExecutor = taskExecutor;
        this.env = env;
    }

    @Override
    public void afterPropertiesSet() throws LiquibaseException {
        if (env.acceptsProfiles(Profiles.of(ProfileConstants.SPRING_PROFILE_DEVELOPMENT))) {
            try (Connection connection = getDataSource().getConnection()) {
                taskExecutor.execute(() -> {
                    try {
                        logger.warn(STARTING_ASYNC_MESSAGE);
                        initDb();
                    } catch (LiquibaseException e) {
                        logger.error(EXCEPTION_MESSAGE, e.getMessage(), e);
                    }
                });
            } catch (SQLException e) {
                logger.error(EXCEPTION_MESSAGE, e.getMessage(), e);
            }
        } else {
            logger.debug(STARTING_SYNC_MESSAGE);
            initDb();
        }
    }

    private void initDb() throws LiquibaseException {
        StopWatch watch = new StopWatch();
        watch.start();
        super.afterPropertiesSet();
        watch.stop();
        logger.debug(STARTED_MESSAGE, watch.getTotalTimeMillis());
        if (watch.getTotalTimeMillis() > SLOWNESS_THRESHOLD * 1000L) {
            logger.warn(SLOWNESS_MESSAGE, SLOWNESS_THRESHOLD);
        }
    }
}
