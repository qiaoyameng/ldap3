"""
Persistent search event iterator.
"""

try:
    from queue import Queue, Full, Empty
except ImportError:  # Python 2
    # noinspection PyUnresolvedReferences
    from Queue import Queue, Full, Empty
from threading import Event

from ... import ALL_ATTRIBUTES, ASYNC_STREAM, DEREF_NEVER, SUBTREE
from ...core.exceptions import LDAPConfigurationError, LDAPExtensionError
from ...protocol.persistentSearch import persistent_search_control, EntryChangeNotificationControl
from ...utils.asn1 import decoder
from ...utils.dn import safe_dn


BLOCK_ON_OVERFLOW = 'block'
RAISE_ON_OVERFLOW = 'raise'

REASON_ABANDONED = 'abandoned'
REASON_SERVER_ENDED = 'server_ended'
REASON_DISCONNECTED = 'disconnected'
REASON_SEARCH_ERROR = 'search_error'
REASON_QUEUE_OVERFLOW = 'queue_overflow'
REASON_RECEIVER_ERROR = 'receiver_error'


class PersistentSearchEvent(object):
    def __init__(self, event_type, dn, previous_dn=None, change_number=None,
                 initial=False, raw_response=None):
        self.event_type = event_type
        self.change_type = None if initial else event_type
        self.dn = dn
        self.previous_dn = previous_dn
        self.old_dn = previous_dn
        self.change_number = change_number
        self.initial = initial
        self.phase = 'initial' if initial else 'change'
        self.raw_response = raw_response

    def __repr__(self):
        return 'PersistentSearchEvent({0!r}, dn={1!r}, previous_dn={2!r}, change_number={3!r}, initial={4!r})'.format(
            self.event_type, self.dn, self.previous_dn, self.change_number, self.initial)


class PersistentSearchEnd(object):
    def __init__(self, reason, result=None, error=None):
        self.reason = reason
        self.result = result
        self.error = error

    def __repr__(self):
        return 'PersistentSearchEnd({0!r})'.format(self.reason)


_TERMINAL_SENTINEL = object()


class PersistentSearchEvents(object):
    def __init__(self,
                 connection,
                 search_base='',
                 search_filter='(objectclass=*)',
                 search_scope=SUBTREE,
                 dereference_aliases=DEREF_NEVER,
                 attributes=ALL_ATTRIBUTES,
                 size_limit=0,
                 time_limit=0,
                 controls=None,
                 changes_only=False,
                 show_additions=True,
                 show_deletions=True,
                 show_modifications=True,
                 show_dn_modifications=True,
                 notifications=True,
                 queue_maxsize=0,
                 on_overflow=BLOCK_ON_OVERFLOW,
                 put_timeout=None):
        if connection.strategy_type != ASYNC_STREAM:
            raise LDAPExtensionError('Persistent search events need an ASYNC_STREAM connection')
        if not notifications:
            raise LDAPConfigurationError('Persistent search events require entry change notifications')
        if not isinstance(queue_maxsize, int) or queue_maxsize < 0:
            raise LDAPConfigurationError('queue_maxsize must be a non-negative integer')
        if on_overflow not in (BLOCK_ON_OVERFLOW, RAISE_ON_OVERFLOW):
            raise LDAPConfigurationError('on_overflow must be block or raise')
        if put_timeout is not None and (not isinstance(put_timeout, (int, float)) or put_timeout < 0):
            raise LDAPConfigurationError('put_timeout must be a non-negative number or None')

        if connection.check_names and search_base:
            search_base = safe_dn(search_base)

        self.connection = connection
        self.base = search_base
        self.filter = search_filter
        self.scope = search_scope
        self.dereference_aliases = dereference_aliases
        self.attributes = attributes
        self.size_limit = size_limit
        self.time_limit = time_limit
        self.changes_only = changes_only
        self.message_id = None
        self.queue = Queue(queue_maxsize)
        self.on_overflow = on_overflow
        self.put_timeout = put_timeout
        self._in_initial_phase = not changes_only
        self._ended = False
        self._closing = False
        self._end = None
        self._terminal = Event()

        change_types = 0
        if show_additions:
            change_types += 1
        if show_deletions:
            change_types += 2
        if show_modifications:
            change_types += 4
        if show_dn_modifications:
            change_types += 8

        request_controls = list(controls) if controls is not None else []
        request_controls.append(persistent_search_control(change_types, changes_only, True))
        self.controls = request_controls

    def __iter__(self):
        if self.message_id is None and not self._ended:
            self.start()
        return self

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()

    def start(self):
        if self.message_id:
            return self
        if self._ended:
            raise LDAPExtensionError('Persistent search event iterator cannot be restarted')

        strategy = self.connection.strategy
        if not self.connection.bound:
            self.connection.bind()

        with strategy.async_lock:
            strategy.add_persistent_search_listener(self._receive_change, self._receive_end)
            strategy.pending_persistent_search = True
            try:
                self.message_id = self.connection.search(search_base=self.base,
                                                         search_filter=self.filter,
                                                         search_scope=self.scope,
                                                         dereference_aliases=self.dereference_aliases,
                                                         attributes=self.attributes,
                                                         size_limit=self.size_limit,
                                                         time_limit=self.time_limit,
                                                         controls=self.controls)
            except Exception:
                strategy.remove_persistent_search_listener(self._receive_change, self._receive_end)
                strategy.persistent_search_message_id = None
                self.message_id = None
                strategy.pending_persistent_search = False
                raise
        return self

    def stop(self):
        if self._closing:
            return

        self._closing = True
        message_id = self.message_id
        if message_id is None and self._end is None:
            return
        outstanding = self.connection.strategy._outstanding
        if message_id is not None and outstanding and message_id in outstanding:
            try:
                self.connection.abandon(message_id)
            except Exception:
                pass

        if not self.connection.closed:
            self.connection.strategy.close()
        if self._end is None:
            self._finish(REASON_ABANDONED)

    def __next__(self):
        return self.next_event()

    next = __next__

    def next_event(self, block=True, timeout=None):
        if self.message_id is None and not self._ended:
            self.start()

        if self._terminal.is_set():
            try:
                item = self.queue.get_nowait()
            except Empty:
                item = _TERMINAL_SENTINEL
        else:
            item = self.queue.get(block, timeout)

        if item is not _TERMINAL_SENTINEL:
            return item

        end = self._end
        self._ended = True
        self._cleanup_message_state()
        raise StopIteration(end)

    @property
    def end(self):
        return self._end

    def _cleanup_message_state(self):
        strategy = self.connection.strategy
        message_id = self.message_id
        self.message_id = None
        if strategy.persistent_search_message_id == message_id:
            strategy.persistent_search_message_id = None
        with strategy.async_lock:
            if strategy._responses is not None and message_id in strategy._responses:
                del strategy._responses[message_id]
            if strategy._outstanding is not None:
                strategy._outstanding.pop(message_id, None)

    def _enqueue(self, item):
        if self.on_overflow == BLOCK_ON_OVERFLOW:
            self.queue.put(item, True, self.put_timeout)
            return

        try:
            self.queue.put_nowait(item)
        except Full as error:
            if self.on_overflow == RAISE_ON_OVERFLOW:
                overflow_error = LDAPConfigurationError('Persistent search event queue is full')
                overflow_error.event = item
                raise overflow_error

    def _finish(self, reason, result=None, error=None):
        if self._end is not None:
            return
        self._end = PersistentSearchEnd(reason, result, error)
        self._terminal.set()
        try:
            self.queue.put_nowait(_TERMINAL_SENTINEL)
        except Full:
            pass

    def _receive_change(self, change):
        if self._end is not None:
            return

        if change.get('type') == 'searchResEntry':
            event = self._build_event(change)
            self._enqueue(event)

    def _receive_end(self, reason, result=None, error=None):
        if reason == REASON_ABANDONED and not self._closing:
            return
        self._finish(reason, result, error)

    def _build_event(self, change):
        controls = change.get('controls') or {}
        notification_control = controls.get('2.16.840.1.113730.3.4.7')
        notification = None
        if notification_control is not None:
            notification = self._decode_notification(notification_control.get('value'))

        if notification is None:
            event_type = 'entry'
            initial = self._in_initial_phase
            previous_dn = None
            change_number = None
        else:
            event_type = self._change_type_name(notification)
            initial = False
            self._in_initial_phase = False
            has_previous_dn = 'previousDN' in notification and notification['previousDN'].hasValue()
            previous_dn = self._as_text(notification['previousDN']) if has_previous_dn else None
            has_change_number = 'changeNumber' in notification and notification['changeNumber'].hasValue()
            change_number = int(notification['changeNumber']) if has_change_number else None

        return PersistentSearchEvent(event_type,
                                     change.get('dn'),
                                     previous_dn,
                                     change_number,
                                     initial,
                                     change)

    @staticmethod
    def _as_text(value):
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.decode('utf-8')
        return str(value)

    @staticmethod
    def _decode_notification(value):
        decoded, unprocessed = decoder.decode(value, asn1Spec=EntryChangeNotificationControl())
        if unprocessed:
            raise LDAPExtensionError('unprocessed value in EntryChangeNotificationControl')
        return decoded

    @staticmethod
    def _change_type_name(notification):
        change_type = int(notification['changeType'])
        return {1: 'add', 2: 'delete', 4: 'modify', 8: 'moddn'}[change_type]
