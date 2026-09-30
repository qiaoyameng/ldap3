"""
Persistent search event stream.
"""

from ...core.exceptions import LDAPExtensionError
from ...strategy.persistentSearchEvents import Empty, PersistentSearchEndEvent, PersistentSearchEventQueue, \
    QUEUE_BLOCK, REASON_ABANDONED


class PersistentSearchEventStream(object):
    def __init__(self,
                 connection,
                 search_base='',
                 search_filter='(objectclass=*)',
                 search_scope=None,
                 dereference_aliases=None,
                 attributes=None,
                 size_limit=0,
                 time_limit=0,
                 controls=None,
                 changes_only=False,
                 show_additions=True,
                 show_deletions=True,
                 show_modifications=True,
                 show_dn_modifications=True,
                 queue_size=None,
                 queue_overflow=QUEUE_BLOCK,
                 on_queue_overflow=None):
        if connection.strategy.sync or not hasattr(connection.strategy, 'add_persistent_search_listener'):
            raise LDAPExtensionError('Persistent search events need an asynchronous streaming connection')

        from ... import SUBTREE, DEREF_NEVER, ALL_ATTRIBUTES, SEQUENCE_TYPES
        from ...protocol.persistentSearch import persistent_search_control
        from ...utils.dn import safe_dn

        search_scope = SUBTREE if search_scope is None else search_scope
        dereference_aliases = DEREF_NEVER if dereference_aliases is None else dereference_aliases
        attributes = ALL_ATTRIBUTES if attributes is None else attributes

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
        self.close_reason = None
        self.close_result = None
        self.close_error = None
        self._queue = PersistentSearchEventQueue(queue_size, queue_overflow, on_queue_overflow)

        if isinstance(controls, SEQUENCE_TYPES):
            self.controls = list(controls)
        elif controls is None:
            self.controls = []
        else:
            self.controls = [controls]

        events_type = 0
        if show_additions:
            events_type += 1
        if show_deletions:
            events_type += 2
        if show_modifications:
            events_type += 4
        if show_dn_modifications:
            events_type += 8

        self.controls.append(persistent_search_control(events_type, changes_only, True))
        self._listener_id = id(self)
        self.start()

    def start(self):
        if self.message_id:
            return

        if not self.connection.bound:
            self.connection.bind()

        with self.connection.strategy.async_lock:
            self.message_id = self.connection.search(search_base=self.base,
                                                     search_filter=self.filter,
                                                     search_scope=self.scope,
                                                     dereference_aliases=self.dereference_aliases,
                                                     attributes=self.attributes,
                                                     size_limit=self.size_limit,
                                                     time_limit=self.time_limit,
                                                     controls=self.controls)
            self.connection.strategy.add_persistent_search_listener(self.message_id, self._listener_id, self._queue)

    def _receive_event(self, block=True, timeout=None):
        try:
            return self._queue.get_event(block, timeout)
        except Empty:
            return None

    def next_event(self, block=True, timeout=None):
        event = self._receive_event(block, timeout)
        if event is None:
            return None
        if isinstance(event, PersistentSearchEndEvent):
            self.close_reason = event.reason
            self.close_result = event.result
            self.close_error = event.error
            self.message_id = None
        return event

    def events(self, timeout=None):
        while True:
            event = self.next_event(True, timeout)
            if event is None:
                return
            if isinstance(event, PersistentSearchEndEvent):
                if event.error:
                    raise event.error
                return
            yield event

    def __iter__(self):
        return self.events()

    def _finish(self, reason, result=None, error=None, send_abandon=False, unbind=False):
        message_id = self.message_id
        self.close_reason = reason
        self.close_result = result
        self.close_error = error
        self._queue.closed = True
        self.message_id = None

        if send_abandon and message_id and not self.connection.closed and message_id in self.connection.strategy._outstanding:
            self.connection.abandon(message_id)
            if self.connection.strategy.persistent_search_message_id == message_id:
                self.connection.strategy.persistent_search_message_id = None

        if send_abandon:
            self._queue.end(PersistentSearchEndEvent(reason, result, error))
        elif hasattr(self.connection.strategy, 'finish_persistent_search_listener'):
            self.connection.strategy.finish_persistent_search_listener(
                message_id, self._listener_id, PersistentSearchEndEvent(reason, result, error))

        if message_id and message_id in self.connection.strategy._responses:
            del self.connection.strategy._responses[message_id]
        if hasattr(self.connection.strategy, '_requests') and self.connection.strategy._requests and message_id in self.connection.strategy._requests:
            del self.connection.strategy._requests[message_id]

        if unbind and not self.connection.closed:
            self.connection.unbind()

    def stop(self, unbind=True):
        if self._queue.end_event.is_set():
            if self.message_id and self.message_id in self.connection.strategy._responses:
                del self.connection.strategy._responses[self.message_id]
            end = self._queue.end_value
            self.close_reason = end.reason
            self.close_result = end.result
            self.close_error = end.error
            self.message_id = None
            if unbind and not self.connection.closed:
                self.connection.unbind()
            return
        self._finish(REASON_ABANDONED, send_abandon=True, unbind=unbind)

    def close(self):
        self.stop(unbind=False)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
