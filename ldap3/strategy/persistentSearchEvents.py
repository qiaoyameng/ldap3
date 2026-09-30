try:
    from queue import Queue, Full, Empty
except ImportError:  # Python 2
    from Queue import Queue, Full, Empty

from threading import Event

from copy import deepcopy

from ..core.exceptions import LDAPExtensionError, LDAPPersistentSearchQueueOverflowError
from ..protocol.persistentSearch import EntryChangeNotificationControl
from ..utils.asn1 import decoder


EVENT_INITIAL = 'initial'
EVENT_ADD = 'add'
EVENT_DELETE = 'delete'
EVENT_MODIFY = 'modify'
EVENT_MODDN = 'moddn'

REASON_COMPLETED = 'completed'
REASON_ABANDONED = 'abandoned'
REASON_DISCONNECTED = 'disconnected'
REASON_ERROR = 'error'

QUEUE_BLOCK = 'block'
QUEUE_ERROR = 'error'

CHANGE_TYPES = {
    1: EVENT_ADD,
    'add': EVENT_ADD,
    2: EVENT_DELETE,
    'delete': EVENT_DELETE,
    4: EVENT_MODIFY,
    'modify': EVENT_MODIFY,
    8: EVENT_MODDN,
    'modify dn': EVENT_MODDN,
    'modDN': EVENT_MODDN,
    'moddn': EVENT_MODDN,
}


class PersistentSearchEvent(object):
    def __init__(self, phase, change_type=None, dn=None, previous_dn=None, change_number=None, response=None):
        self.phase = phase
        self.event_type = EVENT_INITIAL if phase == EVENT_INITIAL else change_type
        self.change_type = None if phase == EVENT_INITIAL else change_type
        self.dn = dn
        self.previous_dn = previous_dn
        self.old_dn = previous_dn
        self.change_number = change_number
        self.attributes = response.get('attributes') if response else None
        self.raw_attributes = response.get('raw_attributes') if response else None
        self.raw_response = response

    def __repr__(self):
        return '{0}(phase={1!r}, change_type={2!r}, dn={3!r})'.format(
            self.__class__.__name__, self.phase, self.change_type, self.dn)


class PersistentSearchEndEvent(object):
    def __init__(self, reason, result=None, error=None):
        self.phase = 'end'
        self.reason = reason
        self.result = result
        self.error = error
        self.raw_response = result


class PersistentSearchEventQueue(object):
    def __init__(self, maxsize=None, on_overflow=QUEUE_BLOCK, overflow_callback=None):
        if on_overflow not in (QUEUE_BLOCK, QUEUE_ERROR):
            raise LDAPExtensionError('invalid persistent search queue overflow policy')
        if overflow_callback is not None and not callable(overflow_callback):
            raise LDAPExtensionError('persistent search overflow callback is not callable')

        self.maxsize = None if not maxsize else maxsize
        self.on_overflow = on_overflow
        self.overflow_callback = overflow_callback
        self.queue = Queue(maxsize if maxsize else 0)
        self.closed = False
        self.end_event = Event()
        self.end_value = None

    def put_event(self, event):
        if self.closed:
            return

        if self.maxsize is None:
            self.queue.put(event)
            return True

        try:
            self.queue.put_nowait(event)
        except Full:
            if self.overflow_callback:
                self.overflow_callback(event)

            if self.on_overflow == QUEUE_ERROR:
                self.closed = True
                self.end_value = PersistentSearchEndEvent(
                    REASON_ERROR,
                    error=LDAPPersistentSearchQueueOverflowError('persistent search event queue is full'))
                self.end_event.set()
                return False

            self.queue.put(event)
        return True

    def get_event(self, block=True, timeout=None):
        if not block:
            try:
                return self.queue.get(False)
            except Empty:
                if self.end_event.is_set():
                    return self.end_value
                raise

        remaining = timeout
        wait_time = 0.01
        while True:
            if self.end_event.is_set():
                try:
                    return self.queue.get(False)
                except Empty:
                    return self.end_value
            try:
                if timeout is None:
                    return self.queue.get(True, wait_time)
                current_wait = min(wait_time, remaining)
                event = self.queue.get(True, current_wait)
                remaining -= current_wait
                return event
            except Empty:
                if timeout is None:
                    continue
                remaining -= current_wait
                if remaining <= 0:
                    raise

    def end(self, event):
        self.closed = True
        self.end_value = event
        self.end_event.set()


def _entry_change(change):
    notification = change.get('controls', {}).get('2.16.840.1.113730.3.4.7')
    if not notification:
        return None

    value = notification.get('value')
    if value is None:
        return None

    if isinstance(value, dict):
        change_type = CHANGE_TYPES.get(value.get('changeType'))
        previous_dn = value.get('previousDN')
        change_number = value.get('changeNumber')
    else:
        decoded, unprocessed = decoder.decode(value, asn1Spec=EntryChangeNotificationControl())
        if unprocessed:
            raise LDAPExtensionError('unprocessed value in EntryChangeNotificationControl')
        change_type = CHANGE_TYPES.get(int(decoded['changeType']))
        previous_dn = str(decoded['previousDN']) if decoded['previousDN'].hasValue() else None
        change_number = int(decoded['changeNumber']) if decoded['changeNumber'].hasValue() else None

    if change_type is None:
        raise LDAPExtensionError('unknown persistent search change type')

    return PersistentSearchEvent(change_type,
                                 change_type,
                                 change.get('dn'),
                                 previous_dn,
                                 change_number,
                                 deepcopy(change))


def persistent_search_event(change):
    event = _entry_change(change)
    if event:
        return event
    return PersistentSearchEvent(EVENT_INITIAL,
                                 None,
                                 change.get('dn'),
                                 None,
                                 None,
                                 deepcopy(change))
