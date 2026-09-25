#!/usr/bin/env python3
"""
worker.py - Background thread workers.

BkpsWorker  - one-shot: runs a callable, emits finished/error.
MonitorWorker - long-running: runs with a stop_event, emits stopped when done.
"""

import time
import threading
import inspect
import traceback
from typing import Any, Callable

from PySide6.QtCore import QThread, Signal


class BkpsWorker(QThread):
    """
    Run *fn(*args, **kwargs)* in a background thread.

    Special kwargs (popped before calling fn):
        _setup    : callable invoked at thread start (before fn)
                    Use this to call StdoutCapture.register_thread() so that
                    sys.stdout writes from this thread are routed to the right LogPanel.
        _teardown : callable invoked at thread end (after fn, in finally block)
                    Use this to call StdoutCapture.unregister_thread().

    Signals
    -------
    finished(object)  - emitted with the function's return value on success
    error(str)        - emitted with a traceback string on exception
    """
    task_done = Signal(object)
    error = Signal(str)

    def __init__(self, fn: Callable, *args, **kwargs):
        super().__init__()
        self._setup = kwargs.pop("_setup", None)
        self._teardown = kwargs.pop("_teardown", None)
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self._cancel_event = threading.Event()

    def request_cancel(self) -> None:
        """Request cooperative cancellation for this worker.

        Sets the internal cancel event. The running function must
        periodically check *_cancel_event* (passed as a kwarg when
        the function signature declares it) to honour the request.
        """
        self._cancel_event.set()

    @property
    def is_cancelled(self) -> bool:
        """True if cancellation has been requested via request_cancel()."""
        return self._cancel_event.is_set()

    # ── QThread.run override ───────────────────────────────────────────────

    def run(self) -> None:
        """Execute the wrapped callable on the worker thread.

        Lifecycle:
            1. _setup() → registers this thread with StdoutCapture.
            2. fn() → the actual work; _cancel_event injected if declared.
            3. _teardown() → unregisters the thread so final output is flushed.
            4. Brief sleep → lets the Qt event loop drain buffered log lines.
            5. Emit task_done or error on the main thread via signals.
        """
        result = None
        error_occurred = False
        try:
            if self._setup:
                self._setup()

            # Inject _cancel_event into kwargs only if the callable declares it.
            # inspect.signature() may raise for built-ins — handled gracefully.
            fn_kwargs = dict(self._kwargs)
            try:
                sig = inspect.signature(self._fn)
                if "_cancel_event" in sig.parameters:
                    fn_kwargs["_cancel_event"] = self._cancel_event
            except (TypeError, ValueError):
                pass

            result = self._fn(*self._args, **fn_kwargs)
        except Exception:
            error_occurred = True
            error_tb = traceback.format_exc()
        finally:
            # Teardown FIRST so StdoutCapture flushes buffered lines before
            # the completion signal triggers any UI state change.
            if self._teardown:
                try:
                    self._teardown()
                except Exception:
                    pass

            # Brief sleep gives the 50 ms drain timer at least one full cycle
            # to push remaining log lines to the LogPanel before the tab
            # re-enables buttons and shows the completion banner.
            time.sleep(1.0)
            if error_occurred:
                self.error.emit(error_tb)
            else:
                self.task_done.emit(result)


# ── MonitorWorker ─────────────────────────────────────────────────────────

class MonitorWorker(QThread):
    """
    Long-running worker for operations that need graceful cancellation
    (e.g. log tailing, server monitoring).

    Unlike BkpsWorker (which runs a one-shot callable), MonitorWorker
    passes a threading.Event as the first positional argument to *fn*.
    The callable is expected to loop until that event is set.

    Signals
    -------
    stopped()   - emitted when the callable returns (for any reason)
    error(str)  - emitted with formatted traceback on exception
    """
    stopped = Signal()
    error = Signal(str)

    def __init__(self, fn: Callable, *args, **kwargs):
        """Initialise a long-running monitor worker.

        Args:
            fn: Callable that accepts a threading.Event as its first
                argument followed by *args and **kwargs.  It should
                return when the event is set.
            *args: Positional arguments forwarded to fn (after the event).
            **kwargs: Keyword arguments forwarded to fn.
        """
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        # Public so callers can pass it into nested helpers if needed.
        self.stop_event = threading.Event()

    def run(self) -> None:
        """Run the monitor callable on the worker thread.

        The stop_event is passed as the first argument. The stopped
        signal is always emitted in the finally block so the caller
        can clean up regardless of whether fn raised.
        """
        try:
            self._fn(self.stop_event, *self._args, **self._kwargs)
        except Exception:
            self.error.emit(traceback.format_exc())
        finally:
            # Always emit stopped so the caller can re-enable UI controls.
            self.stopped.emit()

    def request_stop(self) -> None:
        """Signal the worker to stop and block until it finishes.

        Sets the stop_event (which fn should check) then waits up to
        5 seconds for the thread to exit.  Any cleanup that fn performs
        in its finally block will have completed when this returns.
        """
        self.stop_event.set()
        self.wait(5000)  # wait up to 5 s
