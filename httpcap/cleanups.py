from __future__ import unicode_literals, print_function, division

import threading

# atexit not work for signal...
_cleanup_functions = []
_lock = threading.Lock()
_cleaned = False


def register(function):
    _cleanup_functions.append(function)


def cleanup():
    global _cleaned
    _lock.acquire()
    try:
        if not _cleaned:
            for f in _cleanup_functions:
                try:
                    f()
                except Exception:
                    pass
            _cleaned = True
    finally:
        _lock.release()
