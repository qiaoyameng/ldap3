"""
"""

# Created on 2016.07.10
#
# Author: Giovanni Cannata
#
# Copyright 2016 - 2025 Giovanni Cannata
#
# This file is part of ldap3.
#
# ldap3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ldap3 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ldap3 in the COPYING and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.

try:
    from queue import Queue
except ImportError:  # Python 2
    # noinspection PyUnresolvedReferences
    from Queue import Queue

from io import StringIO
from os import linesep

from ..protocol.rfc2849 import decode_persistent_search_control
from ..strategy.asynchronous import AsyncStrategy
from ..core.exceptions import LDAPLDIFError
from ..utils.conv import prepare_for_stream
from ..protocol.rfc2849 import persistent_search_response_to_ldif, add_ldif_header
from .persistentSearchEvents import persistent_search_event, PersistentSearchEndEvent, \
    REASON_COMPLETED, REASON_DISCONNECTED


# noinspection PyProtectedMember
class AsyncStreamStrategy(AsyncStrategy):
    """
    This strategy is asynchronous. It streams responses in a generator as they appear in the self._responses container
    """
    def __init__(self, ldap_connection):
        AsyncStrategy.__init__(self, ldap_connection)
        self.can_stream = True
        self.line_separator = linesep
        self.all_base64 = False
        self.stream = None
        self.order = dict()
        self._header_added = False
        self.persistent_search_message_id = None
        self.streaming = False
        self.callback = None
        if ldap_connection.pool_size:
            self.events = Queue(ldap_connection.pool_size)
        else:
            self.events = Queue()
        self._persistent_search_listeners = dict()
        self._pending_disconnect_event = None
        self._pending_error_event = None

        del self._requests  # remove _requests dict from Async Strategy

    def _persistent_search_listeners_for_message(self, message_id):
        return dict(self._persistent_search_listeners.get(message_id, {}))

    def add_persistent_search_listener(self, message_id, listener_id, event_queue):
        if message_id not in self._persistent_search_listeners:
            self._persistent_search_listeners[message_id] = dict()
        self._persistent_search_listeners[message_id][listener_id] = event_queue

    def remove_persistent_search_listener(self, message_id, listener_id):
        listeners = self._persistent_search_listeners.get(message_id)
        if listeners:
            listeners.pop(listener_id, None)
            if not listeners:
                del self._persistent_search_listeners[message_id]

    def finish_persistent_search_listener(self, message_id, listener_id, event):
        listeners = self._persistent_search_listeners.get(message_id)
        if listeners and listener_id in listeners:
            listeners[listener_id].end(event)
            self.remove_persistent_search_listener(message_id, listener_id)

    def _discard_persistent_search_responses(self, message_id):
        with self.async_lock:
            self._responses.pop(message_id, None)

    def _notify_persistent_search_listeners_set(self, message_id, change, listeners):
        if not listeners:
            return True

        if change['type'] == 'searchResEntry':
            event = persistent_search_event(change)
        elif change['type'] == 'searchResDone':
            event = PersistentSearchEndEvent(REASON_COMPLETED, change)
        else:
            return True

        accepted = True
        for listener_id, listener in list(listeners.items()):
            if not listener.put_event(event):
                accepted = False
                self._pending_error_event = listener.end_value
                self.remove_persistent_search_listener(message_id, listener_id)

        if change['type'] == 'searchResDone':
            self._persistent_search_listeners.pop(message_id, None)
            self._discard_persistent_search_responses(message_id)
        elif not accepted:
            self.connection.listening = False
        return accepted

    def close(self):
        listener_ids = list(self._persistent_search_listeners.items())
        ending = any(not listener.end_event.is_set() for _, listeners in listener_ids for listener in listeners.values())
        if ending:
            event = PersistentSearchEndEvent(REASON_DISCONNECTED)
            self._pending_disconnect_event = event
        for message_id, listeners in listener_ids:
            if not ending:
                self._discard_persistent_search_responses(message_id)
                self._persistent_search_listeners.pop(message_id, None)
        if not ending or self.connection.closed:
            AsyncStrategy.close(self)

    def complete_disconnected_persistent_searches(self):
        event = getattr(self, '_pending_disconnect_event', None)
        if not event:
            return
        for message_id, listeners in list(self._persistent_search_listeners.items()):
            for listener in list(listeners.values()):
                listener.end(event)
            self._discard_persistent_search_responses(message_id)
        self._persistent_search_listeners.pop(message_id, None)
        self._pending_disconnect_event = None
        self._pending_error_event = None
        if not self.connection.closed and self.connection.listening:
            AsyncStrategy.close(self)

    def complete_overflowing_persistent_searches(self):
        event = self._pending_error_event
        if not event:
            return
        for message_id, listeners in list(self._persistent_search_listeners.items()):
            for listener in list(listeners.values()):
                listener.end(event)
            self._discard_persistent_search_responses(message_id)
            self._persistent_search_listeners.pop(message_id, None)
        self._pending_error_event = None
        if not self.connection.closed and self.connection.listening:
            AsyncStrategy.close(self)

    def _start_listen(self):
        AsyncStrategy._start_listen(self)
        if self.streaming:
            if not self.stream or (isinstance(self.stream, StringIO) and self.stream.closed):
                self.set_stream(StringIO())

    def _stop_listen(self):
        AsyncStrategy._stop_listen(self)
        if self.streaming:
            self.stream.close()

    def accumulate_stream(self, message_id, change):
        accepted = True
        listeners = self._persistent_search_listeners_for_message(message_id)
        if message_id == self.persistent_search_message_id:
            with self.async_lock:
                self._responses[message_id] = []
            self._notify_persistent_search_listeners_set(message_id, change, listeners)
            if self.streaming:
                if not self._header_added and self.stream.tell() == 0:
                    header = add_ldif_header(['-'])[0]
                    self.stream.write(prepare_for_stream(header + self.line_separator + self.line_separator))
                ldif_lines = persistent_search_response_to_ldif(change)
                if self.stream and ldif_lines and not self.connection.closed:
                    fragment = self.line_separator.join(ldif_lines)
                    if not self._header_added and self.stream.tell() == 0:
                        self._header_added = True
                        header = add_ldif_header(['-'])[0]
                        self.stream.write(prepare_for_stream(header + self.line_separator + self.line_separator))
                    self.stream.write(prepare_for_stream(fragment + self.line_separator + self.line_separator))
            else:  # strategy is not streaming, events are added to a queue
                notification = decode_persistent_search_control(change)
                if notification:
                    change.update(notification)
                    del change['controls']['2.16.840.1.113730.3.4.7']
                if not self.callback:
                    self.events.put(change)
                else:
                    self.callback(change)
        elif message_id in self._persistent_search_listeners:
            accepted = self._notify_persistent_search_listeners_set(message_id, change, listeners)
        return accepted

    def get_stream(self):
        if self.streaming:
            return self.stream
        return None

    def set_stream(self, value):
        error = False
        try:
            if not value.writable():
                error = True
        except (ValueError, AttributeError):
            error = True

        if error:
            raise LDAPLDIFError('stream must be writable')

        self.stream = value
        self.streaming = True
