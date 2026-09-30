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
    from queue import Queue, Full
except ImportError:  # Python 2
    # noinspection PyUnresolvedReferences
    from Queue import Queue, Full

from io import StringIO
from os import linesep

from ..protocol.rfc2849 import decode_persistent_search_control
from ..strategy.asynchronous import AsyncStrategy
from ..core.exceptions import LDAPConfigurationError, LDAPLDIFError
from ..core.results import RESULT_SUCCESS
from ..utils.conv import prepare_for_stream
from ..protocol.rfc2849 import persistent_search_response_to_ldif, add_ldif_header


class ReceiverSocketThread(AsyncStrategy.ReceiverSocketThread):
    def run(self):
        try:
            AsyncStrategy.ReceiverSocketThread.run(self)
        except Exception as error:
            from ..extend.standard.PersistentSearchEvents import REASON_RECEIVER_ERROR
            self.connection.strategy.end_persistent_search(REASON_RECEIVER_ERROR, error=error)
            try:
                self.connection.strategy.close()
            except Exception:
                pass
            raise


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
        self.remote_disconnect = False
        self.local_close = False
        self.streaming = False
        self.callback = None
        if ldap_connection.pool_size:
            self.events = Queue(ldap_connection.pool_size)
        else:
            self.events = Queue()
        self._persistent_search_listeners = []
        self.pending_persistent_search = False

        del self._requests  # remove _requests dict from Async Strategy

    def _start_listen(self):
        if not self.connection.listening:
            self.local_close = False
            self.remote_disconnect = False
            self.receiver = ReceiverSocketThread(self.connection)
            self.connection.listening = True
            self.receiver.daemon = True
            self.receiver.start()
        if self.streaming:
            if not self.stream or (isinstance(self.stream, StringIO) and self.stream.closed):
                self.set_stream(StringIO())

    def _stop_listen(self):
        AsyncStrategy._stop_listen(self)
        if self.streaming:
            self.stream.close()

    def prepare_stream_send(self, ldap_message):
        if self.pending_persistent_search:
            self.persistent_search_message_id = int(ldap_message['messageID'])
            self.pending_persistent_search = False

    def accumulate_stream(self, message_id, change):
        if message_id == self.persistent_search_message_id:
            with self.async_lock:
                self._responses[message_id] = []
            listeners = list(self._persistent_search_listeners)
            if listeners:
                if change.get('type') == 'searchResDone':
                    reason = self._persistent_search_end_reason(change)
                    for change_listener, end_listener in listeners:
                        if end_listener is not None:
                            self._notify_listener(end_listener, reason, change)
                    return

                for change_listener, end_listener in listeners:
                    self._notify_listener(change_listener, change)
                return

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

    @staticmethod
    def _persistent_search_end_reason(result):
        from ..extend.standard.PersistentSearchEvents import REASON_SEARCH_ERROR, REASON_SERVER_ENDED
        if result.get('result', RESULT_SUCCESS) == RESULT_SUCCESS:
            return REASON_SERVER_ENDED
        return REASON_SEARCH_ERROR

    def add_persistent_search_listener(self, change_listener, end_listener=None):
        self._persistent_search_listeners.append((change_listener, end_listener))

    def remove_persistent_search_listener(self, change_listener, end_listener=None):
        self._persistent_search_listeners = [listener for listener in self._persistent_search_listeners
                                             if listener != (change_listener, end_listener)]

    def end_persistent_search(self, reason, result=None, error=None):
        listeners = list(self._persistent_search_listeners)
        self._persistent_search_listeners = []
        for change_listener, end_listener in listeners:
            if end_listener is not None:
                self._notify_listener(end_listener, reason, result, error)

    def close(self):
        remote_close = self.remote_disconnect
        self.local_close = True
        AsyncStrategy.close(self)
        if remote_close:
            from ..extend.standard.PersistentSearchEvents import REASON_DISCONNECTED
            self.end_persistent_search(REASON_DISCONNECTED)
        else:
            from ..extend.standard.PersistentSearchEvents import REASON_ABANDONED
            self.end_persistent_search(REASON_ABANDONED)

    def _notify_listener(self, listener, *args):
        try:
            listener(*args)
        except (Full, Exception) as error:
            from ..extend.standard.PersistentSearchEvents import REASON_QUEUE_OVERFLOW, REASON_RECEIVER_ERROR
            if isinstance(error, (Full, LDAPConfigurationError)):
                reason = REASON_QUEUE_OVERFLOW
            else:
                reason = REASON_RECEIVER_ERROR
            self.end_persistent_search(reason, error=error)

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
