"""
"""

import threading
import unittest

from pyasn1.codec.ber import encoder
from pyasn1.type.univ import Integer

from ldap3 import ASYNC_STREAM, NONE, Server, Connection
from ldap3.protocol.persistentSearch import ChangeType, EntryChangeNotificationControl
from ldap3.protocol.rfc4511 import LDAPDN
from ldap3.extend.standard.PersistentSearchEvents import PersistentSearchEvents, REASON_ABANDONED, \
    REASON_DISCONNECTED, REASON_QUEUE_OVERFLOW, REASON_SERVER_ENDED, RAISE_ON_OVERFLOW


ECN_OID = '2.16.840.1.113730.3.4.7'
MESSAGE_ID = 7


def ecn_value(change_type, previous_dn=None, change_number=None):
    notification = EntryChangeNotificationControl()
    notification.setComponentByName('changeType', ChangeType(change_type))
    if previous_dn is not None:
        notification.setComponentByName('previousDN', LDAPDN(previous_dn))
    if change_number is not None:
        notification.setComponentByName('changeNumber', Integer(change_number))
    return encoder.encode(notification)


def search_entry(dn, change_type=None, previous_dn=None, change_number=None):
    response = {
        'type': 'searchResEntry',
        'dn': dn,
        'attributes': {'cn': dn.split(',')[0][3:]},
        'raw_attributes': {'cn': [dn.split(',')[0][3:].encode('utf-8')]},
        'controls': {}
    }
    if change_type is not None:
        response['controls'][ECN_OID] = {
            'description': 'Entry Change Notification',
            'criticality': False,
            'value': ecn_value(change_type, previous_dn, change_number)
        }
    return response


def search_done(result=0):
    return {
        'type': 'searchResDone',
        'result': result,
        'description': 'success' if result == 0 else 'operationsError',
        'dn': '',
        'message': '',
        'referrals': []
    }


class FakePersistentSearchServer(threading.Thread):
    def __init__(self, strategy, messages=None, close_after=None, done=None):
        threading.Thread.__init__(self)
        self.daemon = True
        self.strategy = strategy
        self.messages = messages or []
        self.close_after = close_after
        self.done = done
        self.abandoned = threading.Event()

    def run(self):
        for message in self.messages:
            self.strategy.accumulate_stream(MESSAGE_ID, message)
        if self.done is not None:
            self.strategy.accumulate_stream(MESSAGE_ID, self.done)
        if self.close_after is not None:
            self.close_after.wait(5)
        if self.close_after is not None and self.strategy.remote_disconnect:
            self.strategy.close()

    def close_remote(self):
        self.strategy.remote_disconnect = True
        self.strategy.close()


class TestPersistentSearchEvents(unittest.TestCase):
    def make_connection(self):
        connection = Connection(Server('127.0.0.1', get_info=NONE),
                                client_strategy=ASYNC_STREAM,
                                auto_bind=False,
                                raise_exceptions=False)
        connection.bound = True
        def search(*args, **kwargs):
            connection.strategy.prepare_stream_send({'messageID': MESSAGE_ID})
            return MESSAGE_ID

        connection.search = search
        connection.strategy._responses = {MESSAGE_ID: []}
        connection.strategy._outstanding = {MESSAGE_ID: {'type': 'searchRequest', 'controls': []}}
        self.addCleanup(self.close_connection, connection)
        return connection

    @staticmethod
    def close_connection(connection):
        if not connection.closed:
            connection.bound = False
            connection.closed = True

    def make_events(self, connection, **kwargs):
        events = PersistentSearchEvents(connection, 'dc=example,dc=com', **kwargs)
        events.start()
        self.addCleanup(events.stop)
        return events

    def test_initial_rename_and_delete_keep_order_and_disconnect_reason(self):
        connection = self.make_connection()
        events = self.make_events(connection)
        connection.abandon = lambda message_id: True
        server = FakePersistentSearchServer(connection.strategy, [
            search_entry('cn=initial,dc=example,dc=com'),
            search_entry('cn=renamed,dc=example,dc=com', 8,
                         'cn=original,dc=example,dc=com', 201),
            search_entry('cn=renamed,dc=example,dc=com', 2, None, 202)
        ])
        server.start()
        disconnect_timer = threading.Timer(0.1, server.close_remote)
        disconnect_timer.start()

        received = list(events)
        disconnect_timer.join()

        self.assertEqual(['entry', 'moddn', 'delete'], [event.event_type for event in received])
        self.assertEqual([None, 'moddn', 'delete'], [event.change_type for event in received])
        self.assertEqual([True, False, False], [event.initial for event in received])
        self.assertEqual(['cn=initial,dc=example,dc=com', 'cn=renamed,dc=example,dc=com',
                          'cn=renamed,dc=example,dc=com'], [event.dn for event in received])
        self.assertIsNone(received[0].previous_dn)
        self.assertEqual('cn=original,dc=example,dc=com', received[1].previous_dn)
        self.assertEqual('cn=original,dc=example,dc=com', received[1].old_dn)
        self.assertIsNone(received[2].previous_dn)
        self.assertEqual([None, 201, 202], [event.change_number for event in received])
        self.assertTrue(all(event.raw_response['type'] == 'searchResEntry' for event in received))
        self.assertEqual(REASON_DISCONNECTED, events.end.reason)
        server.join(5)
        self.assertFalse(server.is_alive())

    def test_server_search_result_done_ends_iterator(self):
        connection = self.make_connection()
        events = self.make_events(connection)
        server = FakePersistentSearchServer(connection.strategy,
                                            [search_entry('cn=initial,dc=example,dc=com')],
                                            done=search_done())
        server.start()

        received = list(events)

        self.assertEqual(1, len(received))
        self.assertEqual('entry', received[0].event_type)
        self.assertEqual(REASON_SERVER_ENDED, events.end.reason)
        self.assertEqual('searchResDone', events.end.result['type'])
        server.join(5)
        self.assertFalse(server.is_alive())

    def test_stop_sends_abandon_and_wakes_blocking_iterator(self):
        connection = self.make_connection()
        events = self.make_events(connection)
        abandon_received = threading.Event()
        connection.abandon = lambda message_id: abandon_received.set()
        server = FakePersistentSearchServer(connection.strategy,
                                            [search_entry('cn=initial,dc=example,dc=com')])
        server.start()

        first_event = threading.Event()
        waiting_for_next = threading.Event()

        def consume():
            first = events.next_event()
            self.assertEqual('entry', first.event_type)
            first_event.set()
            waiting_for_next.set()
            try:
                events.next_event()
            except StopIteration:
                return

        consumer = threading.Thread(target=consume)
        consumer.start()
        self.assertTrue(first_event.wait(5))
        self.assertTrue(waiting_for_next.wait(5))
        events.stop()
        consumer.join(5)

        self.assertFalse(consumer.is_alive())
        self.assertTrue(abandon_received.is_set())
        self.assertEqual(REASON_ABANDONED, events.end.reason)

    def test_bounded_queue_raises_instead_of_dropping_event(self):
        connection = self.make_connection()
        events = self.make_events(connection, queue_maxsize=1, on_overflow=RAISE_ON_OVERFLOW)
        server = FakePersistentSearchServer(connection.strategy, [
            search_entry('cn=first,dc=example,dc=com'),
            search_entry('cn=second,dc=example,dc=com', 1, None, 301)
        ])
        server.start()

        self.assertTrue(self.wait_for_end(events, 5))
        received = list(events)

        self.assertEqual(['entry'], [event.event_type for event in received])
        self.assertEqual(REASON_QUEUE_OVERFLOW, events.end.reason)
        self.assertEqual('add', events.end.error.event.event_type)
        self.assertEqual(301, events.end.error.event.change_number)
        server.join(5)
        self.assertFalse(server.is_alive())

    @staticmethod
    def wait_for_end(events, timeout):
        timer = threading.Event()
        deadline = threading.Timer(timeout, timer.set)
        deadline.start()
        while events.end is None and not timer.is_set():
            timer.wait(0.01)
        deadline.cancel()
        return events.end is not None


if __name__ == '__main__':
    unittest.main()
