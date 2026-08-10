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

package com.intel.bkp.bkps.config;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.task.AsyncTaskExecutor;

import java.util.concurrent.Callable;
import java.util.concurrent.Future;

@Slf4j
@AllArgsConstructor
public class ExceptionHandlingAsyncTaskExecutor implements AsyncTaskExecutor, InitializingBean, DisposableBean {

    private static final String EXCEPTION_MESSAGE = "Caught async exception";

    private final AsyncTaskExecutor executor;

    @Override
    public void execute(Runnable task) {
        executor.execute(createWrappedRunnable(task));
    }

    @SuppressWarnings("deprecation")
    @Override
    public void execute(Runnable task, long startTimeout) {
        executor.execute(createWrappedRunnable(task));
    }

    private <T> Callable<T> createCallable(final Callable<T> task) {
        return () -> {
            try {
                return task.call();
            } catch (Exception e) {
                handle(e);
                throw e;
            }
        };
    }

    private Runnable createWrappedRunnable(final Runnable task) {
        return () -> {
            try {
                task.run();
            } catch (Exception e) {
                handle(e);
            }
        };
    }

    private void handle(Exception e) {
        log.error(EXCEPTION_MESSAGE, e);
    }

    @Override
    public Future<?> submit(Runnable task) {
        return executor.submit(createWrappedRunnable(task));
    }

    @Override
    public <T> Future<T> submit(Callable<T> task) {
        return executor.submit(createCallable(task));
    }

    @Override
    public void destroy() throws Exception {
        if (executor instanceof final DisposableBean bean) {
            bean.destroy();
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        if (executor instanceof final InitializingBean bean) {
            bean.afterPropertiesSet();
        }
    }
}
