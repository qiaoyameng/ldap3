"""
"""

# Created on 2026.09.30
#
# Author: Giovanni Cannata
#
# Copyright 2013 - 2025 Giovanni Cannata
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


import unittest

from ldap3 import Server, Connection, MOCK_SYNC, MOCK_ASYNC, MODIFY_REPLACE, MODIFY_INCREMENT
from ldap3.core.results import RESULT_SUCCESS, RESULT_ASSERTION_FAILED, RESULT_NO_SUCH_OBJECT, RESULT_UNAVAILABLE_CRITICAL_EXTENSION
from ldap3.protocol.controls import build_control
from ldap3.protocol.rfc4528 import assertion_control
from ldap3.strategy.base import BaseStrategy
from test.config import random_id

testcase_id = ''


def read_entry(connection, dn, attributes):
    message_id = connection.search(dn, '(sn=*)', attributes=attributes)
    if message_id is not True:  # asynchronous strategies return a message id
        response, _ = connection.get_response(message_id)
    else:
        response = connection.response
    return response[0]['attributes'] if response else None


class Test(unittest.TestCase):
    def setUp(self):
        global testcase_id
        testcase_id = random_id()
        # a single mock server (and its DIT) shared by two connections
        self.server = Server('assertion-demo')
        self.connection_1 = Connection(self.server, user='cn=user1,o=lab', password='test1111', client_strategy=MOCK_SYNC)
        self.connection_2 = Connection(self.server, user='cn=user2,o=lab', password='test2222', client_strategy=MOCK_SYNC)
        self.connection_1_async = Connection(self.server, user='cn=user1,o=lab', password='test1111', client_strategy=MOCK_ASYNC)
        self.connection_2_async = Connection(self.server, user='cn=user2,o=lab', password='test2222', client_strategy=MOCK_ASYNC)
        self.entry_dn = 'cn=' + testcase_id + 'entry,o=lab'
        self.connection_1.strategy.add_entry(self.entry_dn, {'sn': 'original_sn', 'revision': 0, 'title': ['title1', 'title2'], 'guid': '07039e68-4373-264d-a0a7-000000000000'})
        self.connection_1.bind()
        self.connection_2.bind()
        self.connection_1_async.bind()
        self.connection_2_async.bind()

    def tearDown(self):
        self.connection_1.unbind()
        self.connection_2.unbind()
        self.connection_1_async.unbind()
        self.connection_2_async.unbind()

    def test_assertion_control_roundtrip(self):
        control = assertion_control('(&(revision=0)(!(sn=locked)))')
        decoded_control = BaseStrategy.decode_control(control)
        self.assertEqual(decoded_control[0], '1.3.6.1.1.12')
        self.assertTrue(decoded_control[1]['criticality'])
        self.assertEqual(decoded_control[1]['value']['filter'], '(&(revision=0)(!(sn=locked)))')

    def test_two_connections_same_version_only_one_modify_succeeds(self):
        # both connections read the entry at the same version (revision=0)
        revision_1 = read_entry(self.connection_1, self.entry_dn, ['revision'])['revision'][0]
        revision_2 = read_entry(self.connection_2, self.entry_dn, ['revision'])['revision'][0]
        self.assertEqual(revision_1, revision_2)
        # both connections modify the entry asserting the version they read
        controls_1 = [assertion_control('(revision=' + str(revision_1) + ')')]
        controls_2 = [assertion_control('(revision=' + str(revision_2) + ')')]
        self.assertTrue(self.connection_1.modify(self.entry_dn, {'sn': [(MODIFY_REPLACE, ['modified_by_conn_1'])], 'revision': [(MODIFY_INCREMENT, [1])]}, controls=controls_1))
        self.assertTrue(self.connection_2.modify(self.entry_dn, {'sn': [(MODIFY_REPLACE, ['modified_by_conn_2'])], 'revision': [(MODIFY_INCREMENT, [1])]}, controls=controls_2) is False)
        self.assertEqual(self.connection_1.result['result'], RESULT_SUCCESS)
        self.assertEqual(self.connection_2.result['result'], RESULT_ASSERTION_FAILED)
        # only the first modification has been applied
        entry = read_entry(self.connection_1, self.entry_dn, ['sn', 'revision'])
        self.assertEqual(entry['sn'], ['modified_by_conn_1'])
        self.assertEqual(entry['revision'], ['1'])

    def test_two_connections_same_version_only_one_modify_succeeds_async(self):
        revision_1 = read_entry(self.connection_1_async, self.entry_dn, ['revision'])['revision'][0]
        revision_2 = read_entry(self.connection_2_async, self.entry_dn, ['revision'])['revision'][0]
        self.assertEqual(revision_1, revision_2)
        message_id_1 = self.connection_1_async.modify(self.entry_dn, {'sn': [(MODIFY_REPLACE, ['modified_by_conn_1'])], 'revision': [(MODIFY_INCREMENT, [1])]}, controls=[assertion_control('(revision=' + str(revision_1) + ')')])
        message_id_2 = self.connection_2_async.modify(self.entry_dn, {'sn': [(MODIFY_REPLACE, ['modified_by_conn_2'])], 'revision': [(MODIFY_INCREMENT, [1])]}, controls=[assertion_control('(revision=' + str(revision_2) + ')')])
        _, result_1 = self.connection_1_async.get_response(message_id_1)
        _, result_2 = self.connection_2_async.get_response(message_id_2)
        self.assertEqual(result_1['result'], RESULT_SUCCESS)
        self.assertEqual(result_2['result'], RESULT_ASSERTION_FAILED)
        entry = read_entry(self.connection_1_async, self.entry_dn, ['sn', 'revision'])
        self.assertEqual(entry['sn'], ['modified_by_conn_1'])
        self.assertEqual(entry['revision'], ['1'])

    def test_assertion_complex_filter(self):
        complex_filter = '(&(revision=0)(|(sn=original_sn)(sn=other_sn))(!(guid=*ffff*))(title=t*))'
        self.assertTrue(self.connection_1.modify(self.entry_dn, {'sn': [(MODIFY_REPLACE, ['complex_ok'])]}, controls=[assertion_control(complex_filter)]))
        self.assertEqual(self.connection_1.result['result'], RESULT_SUCCESS)
        failing_complex_filter = '(&(revision=0)(|(sn=original_sn)(sn=other_sn))(guid=*ffff*))'
        self.assertFalse(self.connection_1.modify(self.entry_dn, {'sn': [(MODIFY_REPLACE, ['complex_ko'])]}, controls=[assertion_control(failing_complex_filter)]))
        self.assertEqual(self.connection_1.result['result'], RESULT_ASSERTION_FAILED)
        self.assertEqual(read_entry(self.connection_1, self.entry_dn, ['sn'])['sn'], ['complex_ok'])

    def test_assertion_failure_is_atomic(self):
        # the whole modification list must not be partially applied when the assertion fails
        self.assertFalse(self.connection_1.modify(self.entry_dn, {'sn': [(MODIFY_REPLACE, ['must_not_be_set'])], 'revision': [(MODIFY_INCREMENT, [1])]}, controls=[assertion_control('(revision=999)')]))
        self.assertEqual(self.connection_1.result['result'], RESULT_ASSERTION_FAILED)
        entry = read_entry(self.connection_1, self.entry_dn, ['sn', 'revision'])
        self.assertEqual(entry['sn'], ['original_sn'])
        self.assertEqual(entry['revision'], ['0'])

    def test_assertion_entry_not_found(self):
        self.assertFalse(self.connection_1.modify('cn=' + testcase_id + 'missing,o=lab', {'sn': [(MODIFY_REPLACE, ['must_not_be_set'])]}, controls=[assertion_control('(revision=0)')]))
        self.assertEqual(self.connection_1.result['result'], RESULT_NO_SUCH_OBJECT)

    def test_unsupported_critical_control_rejected(self):
        manage_dsa_it_critical = build_control('2.16.840.1.113730.3.4.2', True, None)
        self.assertFalse(self.connection_1.modify(self.entry_dn, {'sn': [(MODIFY_REPLACE, ['must_not_be_set'])]}, controls=[manage_dsa_it_critical]))
        self.assertEqual(self.connection_1.result['result'], RESULT_UNAVAILABLE_CRITICAL_EXTENSION)
        self.assertEqual(read_entry(self.connection_1, self.entry_dn, ['sn'])['sn'], ['original_sn'])

    def test_unsupported_non_critical_control_ignored(self):
        manage_dsa_it_not_critical = build_control('2.16.840.1.113730.3.4.2', False, None)
        self.assertTrue(self.connection_1.modify(self.entry_dn, {'sn': [(MODIFY_REPLACE, ['non_critical_ok'])]}, controls=[manage_dsa_it_not_critical]))
        self.assertEqual(self.connection_1.result['result'], RESULT_SUCCESS)
