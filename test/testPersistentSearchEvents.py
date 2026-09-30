"""
"""

import threading
import unittest

try:
    from queue import Queue, Empty
except ImportError:
    from Queue import Queue, Empty

from pyasn1.codec.ber import encoder, decoder as ber_decoder

from ldap3 import Server, Connection, ASYNC_STREAM, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPPersistentSearchQueueOverflowError
from ldap3.strategy.base import BaseStrategy
from ldap3.strategy.asyncStream import AsyncStreamStrategy
from ldap3.protocol.rfc4511 import LDAPMessage, MessageID, ProtocolOp, BindResponse, ResultCode, LDAPDN, \
    SearchResultEntry, SearchResultDone, PartialAttributeList, PartialAttribute, AttributeDescription, Vals, \
    AttributeValue, LDAPString, Control, Controls, LDAPOID, Criticality
from ldap3.protocol.persistentSearch import EntryChangeNotificationControl, ChangeType
from pyasn1.type.univ import Integer


class FakeSocket(object):
    def __init__(self, peer=None):
        self.peer = peer
        self.queue = Queue()
        self.buffer = b''
        self.eof = False
        self.closed = False
        self.family = 2
        self.type = 1

    def connect(self, peer):
        self.peer = peer

    def sendall(self, data):
        if self.closed:
            raise OSError('socket closed')
        self.peer.queue.put(bytes(data))

    def recv(self, size):
        if not self.buffer:
            try:
                self.buffer = self.queue.get_nowait()
            except Empty:
                if self.eof:
                    self.buffer = b''
                else:
                    self.buffer = self.queue.get()
        if not self.buffer:
            return b''
        data = self.buffer[:size]
        self.buffer = self.buffer[size:]
        return data

    def try_recv(self, timeout):
        if self.buffer:
            return True
        try:
            data = self.queue.get(timeout=timeout)
        except Empty:
            return False
        self.buffer = data + self.buffer
        return bool(data)

    def shutdown(self, how):
        pass

    def close(self):
        if not self.closed:
            self.closed = True
            self.peer.eof = True
            self.peer.queue.put(b'')


def socket_pair():
    first = FakeSocket()
    second = FakeSocket(first)
    first.peer = second
    return first, second


class FakePersistentSearchServer(object):
    def __init__(self, disconnect_after_events=False, delay_events=False, delay_before_events=False):
        self.server_socket, self.client_socket = socket_pair()
        self.disconnect_after_events = disconnect_after_events
        self.delay_events = delay_events
        self.delay_before_events = delay_before_events
        self.thread = threading.Thread(target=self.serve)
        self.thread.daemon = True
        self.requests = []
        self.ready_for_abandon = threading.Event()
        self.ready_to_continue = threading.Event()
        self.stop = threading.Event()
        self.error = None

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop.set()
        self.ready_to_continue.set()
        self.server_socket.close()
        self.client_socket.close()
        self.thread.join(2)

    def serve(self):
        try:
            client = self.server_socket
            while not self.stop.is_set():
                message = self._read_message(client)
                if message is None:
                    return
                decoded, _ = ber_decoder.decode(message, asn1Spec=LDAPMessage())
                operation = decoded['protocolOp'].getName()
                message_id = int(decoded['messageID'])
                self.requests.append(operation)

                if operation == 'bindRequest':
                    client.sendall(self._ldap_message(message_id, self._bind_response()))
                elif operation == 'searchRequest':
                    self._send_search_results(client, message_id)
                    if self.disconnect_after_events:
                        client.close()
                        return
                elif operation == 'abandonRequest':
                    self.ready_for_abandon.set()
                    return
                elif operation == 'unbindRequest':
                    self.ready_to_continue.set()
                    client.close()
                    return
        except Exception as exc:
            self.error = exc

    @staticmethod
    def _read_message(client):
        first = client.recv(1)
        if not first:
            return None
        second = client.recv(1)
        if not second:
            return None
        if second[0] < 128:
            length = second[0]
            prefix = first + second
        else:
            count = second[0] & 0x7f
            extra = b''
            while len(extra) < count:
                chunk = client.recv(count - len(extra))
                if not chunk:
                    return None
                extra += chunk
            length = 0
            for byte in bytearray(extra):
                length = (length << 8) + byte
            prefix = first + second + extra
        data = b''
        while len(data) < length:
            chunk = client.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return prefix + data

    @staticmethod
    def _ldap_message(message_id, value, controls=None):
        operation_names = {
            'BindResponse': 'bindResponse',
            'SearchResultEntry': 'searchResEntry',
            'SearchResultDone': 'searchResDone',
        }
        operation_name = operation_names[value.__class__.__name__]
        message = LDAPMessage()
        message['messageID'] = MessageID(message_id)
        message['protocolOp'] = ProtocolOp().setComponentByName(operation_name, value)
        if controls is not None:
            message['controls'] = controls
        return encoder.encode(message)

    @staticmethod
    def _bind_response():
        response = BindResponse()
        response['resultCode'] = ResultCode(0)
        response['matchedDN'] = LDAPDN('')
        response['diagnosticMessage'] = LDAPString('')
        return response

    @staticmethod
    def _done_response():
        response = SearchResultDone()
        response['resultCode'] = ResultCode(0)
        response['matchedDN'] = LDAPDN('')
        response['diagnosticMessage'] = LDAPString('')
        return response

    @staticmethod
    def _entry(dn, cn=None):
        entry = SearchResultEntry()
        entry['object'] = LDAPDN(dn)
        attributes = PartialAttributeList()
        if cn is not None:
            attribute = PartialAttribute()
            attribute['type'] = AttributeDescription('cn')
            values = Vals()
            values.setComponentByPosition(0, AttributeValue(cn.encode('utf-8')))
            attribute['vals'] = values
            attributes.setComponentByPosition(0, attribute)
        entry['attributes'] = attributes
        return entry

    @staticmethod
    def _change_control(change_type, change_number, previous_dn=None):
        value = EntryChangeNotificationControl()
        value['changeType'] = ChangeType(change_type)
        if previous_dn:
            value['previousDN'] = LDAPDN(previous_dn)
        value['changeNumber'] = Integer(change_number)

        control = Control()
        control['controlType'] = LDAPOID('2.16.840.1.113730.3.4.7')
        control['criticality'] = Criticality(False)
        control['controlValue'] = encoder.encode(value)
        controls = Controls()
        controls.setComponentByPosition(0, control)
        return controls

    def _send_search_results(self, client, message_id):
        old_dn = 'cn=old,dc=example,dc=com'
        new_dn = 'cn=new,dc=example,dc=com'
        if self.delay_before_events:
            client.try_recv(0.05)
            return
        client.sendall(self._ldap_message(message_id, self._entry(old_dn, 'old')))
        if self.delay_events:
            if client.try_recv(self.delay_events):
                return
        client.sendall(self._ldap_message(message_id,
                                          self._entry(new_dn, 'new'),
                                          self._change_control('modDN', 2, old_dn)))
        client.sendall(self._ldap_message(message_id,
                                          self._entry(new_dn, 'new'),
                                          self._change_control('delete', 3)))
        if not self.disconnect_after_events and not self.delay_events:
            client.sendall(self._ldap_message(message_id, self._done_response()))


class TestPersistentSearchEvents(unittest.TestCase):
    def _connection(self, fake, fast_decoder=True):
        original_open_socket = BaseStrategy._open_socket

        original_start_listen = AsyncStreamStrategy._start_listen

        def start_fake_listen(strategy):
            original_start_listen(strategy)
            strategy.connection.closed = False

        def open_fake_socket(strategy, address, use_ssl=False, unix_socket=False):
            strategy.connection.socket = fake.client_socket

        BaseStrategy._open_socket = open_fake_socket
        AsyncStreamStrategy._start_listen = start_fake_listen
        self.addCleanup(setattr, BaseStrategy, '_open_socket', original_open_socket)
        self.addCleanup(setattr, AsyncStreamStrategy, '_start_listen', original_start_listen)

        server = Server('127.0.0.1', port=12345, get_info=None)
        return Connection(server,
                          client_strategy=ASYNC_STREAM,
                          authentication=None,
                          auto_bind=False,
                          fast_decoder=fast_decoder,
                          receive_timeout=0)

    def test_initial_changes_order_and_completion_reason(self):
        with FakePersistentSearchServer() as fake:
            connection = self._connection(fake)
            self.assertTrue(connection.bind(read_server_info=False))
            stream = connection.extend.standard.persistent_search_events(
                'dc=example,dc=com', '(objectClass=*)', attributes=ALL_ATTRIBUTES)
            events = list(stream.events(timeout=2))
            self.assertIsNone(fake.error)
            self.assertEqual([event.phase for event in events], ['initial', 'moddn', 'delete'])
            self.assertIsNone(events[0].change_type)
            self.assertEqual(events[0].dn, 'cn=old,dc=example,dc=com')
            self.assertEqual(events[1].old_dn, 'cn=old,dc=example,dc=com')
            self.assertEqual(events[1].dn, 'cn=new,dc=example,dc=com')
            self.assertEqual(events[1].change_number, 2)
            self.assertEqual(events[2].change_number, 3)
            self.assertTrue(events[0].raw_response['dn'])
            self.assertEqual(stream.close_reason, 'completed')
            self.assertEqual(stream.close_result['result'], 0)
            connection.unbind()

    def test_slow_decoder_initial_changes_order_and_completion_reason(self):
        with FakePersistentSearchServer() as fake:
            connection = self._connection(fake, fast_decoder=False)
            self.assertTrue(connection.bind(read_server_info=False))
            stream = connection.extend.standard.persistent_search_events(
                'dc=example,dc=com', '(objectClass=*)', attributes=ALL_ATTRIBUTES)
            events = list(stream.events(timeout=2))
            self.assertEqual([event.phase for event in events], ['initial', 'moddn', 'delete'])
            self.assertEqual(events[1].old_dn, 'cn=old,dc=example,dc=com')
            self.assertEqual(events[2].change_number, 3)
            self.assertEqual(stream.close_reason, 'completed')
            connection.unbind()

    def test_disconnect_has_explicit_reason(self):
        with FakePersistentSearchServer(disconnect_after_events=True) as fake:
            connection = self._connection(fake)
            self.assertTrue(connection.bind(read_server_info=False))
            stream = connection.extend.standard.persistent_search_events()
            events = list(stream.events(timeout=2))
            self.assertEqual([event.change_type for event in events], [None, 'moddn', 'delete'])
            self.assertEqual(stream.close_reason, 'disconnected')
            self.assertTrue(connection.closed)
            self.assertIsNone(fake.error)

    def test_stop_sends_abandon_and_wakes_blocking_iterator(self):
        with FakePersistentSearchServer(delay_events=0.5) as fake:
            connection = self._connection(fake)
            self.assertTrue(connection.bind(read_server_info=False))
            stream = connection.extend.standard.persistent_search_events()
            first = stream.next_event(timeout=2)
            self.assertEqual(first.phase, 'initial')
            stream.stop(unbind=False)
            self.assertEqual([], list(stream.events(timeout=0.1)))
            self.assertEqual(stream.close_reason, 'abandoned')
            self.assertTrue(fake.ready_for_abandon.wait(2))
            self.assertIn('abandonRequest', fake.requests)
            connection.unbind()

    def test_timeout_does_not_look_like_end_of_search(self):
        with FakePersistentSearchServer(delay_before_events=True) as fake:
            connection = self._connection(fake)
            self.assertTrue(connection.bind(read_server_info=False))
            stream = connection.extend.standard.persistent_search_events()
            self.assertIsNone(stream.next_event(block=True, timeout=0.01))
            self.assertIsNone(stream.close_reason)
            self.assertIsNone(fake.error)
            stream.stop(unbind=False)
            fake.ready_for_abandon.wait(2)
            connection.unbind()

    def test_error_queue_overflow_ends_iterator_without_dropping(self):
        overflowed = []
        with FakePersistentSearchServer() as fake:
            connection = self._connection(fake)
            self.assertTrue(connection.bind(read_server_info=False))
            stream = connection.extend.standard.persistent_search_events(
                queue_size=1,
                queue_overflow='error',
                on_queue_overflow=overflowed.append)
            first = stream.next_event(timeout=2)
            self.assertEqual(first.phase, 'initial')
            with self.assertRaises(LDAPPersistentSearchQueueOverflowError):
                list(stream.events(timeout=2))
            self.assertEqual(stream.close_reason, 'error')
            self.assertEqual(len(overflowed), 1)
            self.assertEqual(overflowed[0].change_type, 'moddn')
            self.assertIsNone(fake.error)
            connection.unbind()


if __name__ == '__main__':
    unittest.main()
