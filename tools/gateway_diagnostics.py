"""Bounded operator-only transport diagnostics; never logs requests or error text."""
import json
from pathlib import Path
import re
import sys
import threading
import time

_MAX_EVENTS = 512
_lock = threading.Lock()
_count = 0
_REFUSAL_STAGES = frozenset(('framing', 'ingress', 'body', 'envelope',
    'parameters', 'proof', 'authorization', 'shielded', 'read_batch', 'retained',
    'canonical', 'snapshot', 'snapshot_encoding', 'history', 'forward'))
_SNAPSHOT_STAGES = frozenset(('snapshot_shape',) + tuple(
    prefix + leaf for prefix in ('snapshot_metadata_', 'snapshot_history_')
    for leaf in ('request', 'upstream', 'response')))

def emit(event, **fields):
    global _count
    try:
        with _lock:
            if _count >= _MAX_EVENTS:
                return
            _count += 1
            row = dict(format='zolana090-gateway-diagnostic-v1', sequence=_count, event=event)
            row.update(fields)
            print(json.dumps(row, sort_keys=True, separators=(',', ':')), file=sys.stderr, flush=True)
    except Exception:
        pass  # Diagnostic IO never changes authorization or transport decisions.

def error_fields(error):
    name = type(error).__name__
    name = name if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,63}', name) else 'Exception'
    frame = error.__traceback__
    while frame is not None and frame.tb_next is not None:
        frame = frame.tb_next
    out = dict(exception_class=name)
    if frame is not None:
        out.update(source_file=Path(frame.tb_frame.f_code.co_filename).name[:80],
                   source_function=frame.tb_frame.f_code.co_name[:80], source_line=frame.tb_lineno)
    return out

def handler_class(original):
    class ObservedHandler(original):
        def diagnostic_refusal(self, stage, error, status):
            if stage in _REFUSAL_STAGES and type(status) is int and status in (403, 429):
                emit('http_post_refusal', stage=stage, http_status=status, **error_fields(error))
        def send_response(self, code, message=None):
            self._diagnostic_status = int(code)
            return super().send_response(code, message)
        def do_POST(self):
            began = time.monotonic()
            self._diagnostic_status = 0
            emit('http_post_begin')
            try:
                return super().do_POST()
            except Exception as error:
                emit('http_post_exception', **error_fields(error))
                raise
            finally:
                emit('http_post_end', http_status=self._diagnostic_status,
                     elapsed_ms=round((time.monotonic()-began)*1000, 3))
    return ObservedHandler

def gateway_class(original):
    class ObservedGateway(original):
        def diagnostic_failure(self, stage, error):
            if stage in _SNAPSHOT_STAGES:
                emit('snapshot_read_exception', stage=stage, **error_fields(error))
        def shielded(self, request, proof):
            if request.get('method') != 'getShieldedFeeQuote':
                return super().shielded(request, proof)
            began = time.monotonic()
            emit('fee_quote_begin')
            try:
                result = super().shielded(request, proof)
            except Exception as error:
                emit('fee_quote_exception', **error_fields(error))
                raise
            emit('fee_quote_end', elapsed_ms=round((time.monotonic()-began)*1000, 3))
            return result
    return ObservedGateway

class _Slots:
    def __init__(self, original):
        self._original = original
    def acquire(self, *args, **kwargs):
        result = self._original.acquire(*args, **kwargs)
        if not result:
            emit('listener_slots_exhausted')
        return result
    def release(self, *args, **kwargs):
        return self._original.release(*args, **kwargs)

class _TLSContext:
    def __init__(self, original):
        self._original = original
    def wrap_socket(self, *args, **kwargs):
        began = time.monotonic()
        try:
            result = self._original.wrap_socket(*args, **kwargs)
        except Exception as error:
            emit('tls_handshake_exception', elapsed_ms=round((time.monotonic()-began)*1000, 3),
                 **error_fields(error))
            raise
        emit('tls_handshake_success', elapsed_ms=round((time.monotonic()-began)*1000, 3))
        return result

def server_class(original):
    class ObservedServer(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.slots = _Slots(self.slots)
            self.tls_context = _TLSContext(self.tls_context)
        def handle_error(self, request, address):
            error = sys.exc_info()[1]
            if error is not None:
                emit('request_thread_exception', **error_fields(error))
            # Suppress the default unsanitized traceback, which can include
            # attacker-controlled exception text. The original request still fails.
    return ObservedServer
