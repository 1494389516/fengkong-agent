"""Keep a single in-flight task leased, preserving authenticated data routing."""
from contextlib import contextmanager
from contextvars import copy_context
from threading import Event, Thread


class LeaseLost(RuntimeError):
    pass


@contextmanager
def keep_lease(bus, event, *, lease_seconds=30, interval=10):
    from .event_bus import _lease_window
    _lease_window(lease_seconds)
    if not 0 < interval < lease_seconds:
        raise ValueError('renewal interval must be shorter than lease')
    stop = Event()
    errors = []
    def renew():
        while not stop.wait(interval):
            try:
                if not bus.renew(event.event_id, event.lease_token, lease_seconds=lease_seconds):
                    raise LeaseLost('renewal rejected')
            except Exception as exc:
                errors.append(exc)
                return
    context = copy_context()
    worker = Thread(target=context.run, args=(renew,), daemon=True)
    worker.start()
    try:
        yield
    finally:
        stop.set()
        worker.join()
    if errors:
        raise LeaseLost('lease renewal failed') from errors[0]
