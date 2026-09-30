"""
"""

# Created on 2026.09.30
#
# Author: Giovanni Cannata
#
# Copyright 2026 Giovanni Cannata
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

from ldap3 import Server, Connection, MOCK_SYNC, MOCK_ASYNC, MODIFY_REPLACE, BASE
from ldap3.core.results import RESULT_SUCCESS, RESULT_ASSERTION_FAILED, RESULT_NO_SUCH_OBJECT, RESULT_UNAVAILABLE_CRITICAL_EXTENSION
from ldap3.protocol.controls import build_control
from ldap3.protocol.rfc4528 import assertion_control, decode_assertion_control_value


class Test(unittest.TestCase):
    def setUp(self):
        # two connections sharing the same mock DIT (same Server object)
        self.server = Server('dummy')  # no schema
        self.connection_1 = Connection(self.server, user='cn=admin,o=lab', password='password', client_strategy=MOCK_SYNC)
        self.connection_2 = Connection(self.server, user='cn=admin,o=lab', password='password', client_strategy=MOCK_SYNC)
        self.connection_1.strategy.add_entry('cn=admin,o=lab', {'userPassword': 'password', 'sn': 'admin_sn'})
        self.connection_1.strategy.add_entry('cn=versioned,ou=test,o=lab', {'objectClass': 'person', 'cn': 'versioned', 'sn': 'original_sn', 'revision': '1'})

    def tearDown(self):
        if self.connection_1.bound:
            self.connection_1.unbind()
        if self.connection_2.bound:
            self.connection_2.unbind()

    def test_assertion_control_building(self):
        control = assertion_control('(revision=1)')
        self.assertEqual(str(control['controlType']), '1.3.6.1.1.12')
        self.assertTrue(bool(control['criticality']))  # criticality defaults to True as per RFC 4528
        self.assertEqual(decode_assertion_control_value(bytes(control['controlValue'])), '(revision=1)')

    def test_assertion_control_building_not_critical(self):
        control = assertion_control('(revision=1)', criticality=False)
        self.assertFalse(bool(control['criticality']))

    def test_assertion_control_filter_roundtrip(self):
        for search_filter in ['(&(objectClass=person)(revision>=2)(!(sn=unknown)))',
                              '(|(cn=user*)(sn~=Smith)(title=*))',
                              '(cn:dn:caseIgnoreMatch:=someValue)',
                              '(!(revision<=3))',
                              '(cn=*middle*)']:
            control = assertion_control(search_filter)
            self.assertEqual(decode_assertion_control_value(bytes(control['controlValue'])), search_filter)

    def test_two_connections_same_version_only_one_modify_succeeds(self):
        dn = 'cn=versioned,ou=test,o=lab'
        self.connection_1.bind()
        self.connection_2.bind()
        # both connections read the same version of the entry
        self.connection_1.search(dn, '(objectClass=*)', search_scope=BASE, attributes=['revision'])
        revision_1 = self.connection_1.entries[0]['revision'][0]
        self.connection_2.search(dn, '(objectClass=*)', search_scope=BASE, attributes=['revision'])
        revision_2 = self.connection_2.entries[0]['revision'][0]
        self.assertEqual(revision_1, '1')
        self.assertEqual(revision_2, '1')
        # both connections try to modify the entry asserting the version just read
        controls = [assertion_control('(revision=%s)' % revision_1)]
        self.connection_1.modify(dn, {'revision': (MODIFY_REPLACE, ['2']), 'sn': (MODIFY_REPLACE, ['modified-by-1'])}, controls=controls)
        self.connection_2.modify(dn, {'revision': (MODIFY_REPLACE, ['3']), 'sn': (MODIFY_REPLACE, ['modified-by-2'])}, controls=controls)
        # only the first modify succeeds, the second one gets assertionFailed
        self.assertEqual(self.connection_1.result['result'], RESULT_SUCCESS)
        self.assertEqual(self.connection_2.result['result'], RESULT_ASSERTION_FAILED)
        self.assertEqual(self.connection_2.result['description'], 'assertionFailed')
        # the entry is modified only by the first connection, no partial modification from the second one
        entry = self.server.dit[dn]
        self.assertEqual(entry['revision'], [b'2'])
        self.assertEqual(entry['sn'], [b'modified-by-1'])

    def test_assertion_complex_filter(self):
        dn = 'cn=versioned,ou=test,o=lab'
        self.connection_1.bind()
        # a complex filter matching the entry lets the modify succeed
        self.assertTrue(self.connection_1.modify(dn, {'sn': (MODIFY_REPLACE, ['complex_ok'])}, controls=[assertion_control('(&(objectClass=person)(revision>=1)(|(sn=original*)(cn=other)))')]))
        self.assertEqual(self.connection_1.result['result'], RESULT_SUCCESS)
        self.assertEqual(self.server.dit[dn]['sn'], [b'complex_ok'])
        # a complex filter not matching the entry returns assertionFailed and the modify is not applied at all
        self.assertFalse(self.connection_1.modify(dn, {'sn': (MODIFY_REPLACE, ['must_not_apply']), 'revision': (MODIFY_REPLACE, ['99'])}, controls=[assertion_control('(&(revision=1)(!(sn=complex_ok)))')]))
        self.assertEqual(self.connection_1.result['result'], RESULT_ASSERTION_FAILED)
        self.assertEqual(self.server.dit[dn]['sn'], [b'complex_ok'])
        self.assertEqual(self.server.dit[dn]['revision'], [b'1'])

    def test_assertion_entry_not_found(self):
        self.connection_1.bind()
        self.assertFalse(self.connection_1.modify('cn=nonexistent,ou=test,o=lab', {'sn': (MODIFY_REPLACE, ['must_not_apply'])}, controls=[assertion_control('(revision=1)')]))
        self.assertEqual(self.connection_1.result['result'], RESULT_NO_SUCH_OBJECT)

    def test_unsupported_critical_control_rejected(self):
        dn = 'cn=versioned,ou=test,o=lab'
        self.connection_1.bind()
        self.assertFalse(self.connection_1.modify(dn, {'sn': (MODIFY_REPLACE, ['must_not_apply'])}, controls=[build_control('1.2.3.4', True, None)]))
        self.assertEqual(self.connection_1.result['result'], RESULT_UNAVAILABLE_CRITICAL_EXTENSION)
        self.assertEqual(self.server.dit[dn]['sn'], [b'original_sn'])

    def test_unsupported_noncritical_control_ignored(self):
        dn = 'cn=versioned,ou=test,o=lab'
        self.connection_1.bind()
        self.assertTrue(self.connection_1.modify(dn, {'sn': (MODIFY_REPLACE, ['noncritical_ok'])}, controls=[build_control('1.2.3.4', False, None)]))
        self.assertEqual(self.connection_1.result['result'], RESULT_SUCCESS)
        self.assertEqual(self.server.dit[dn]['sn'], [b'noncritical_ok'])

    def test_two_connections_same_version_only_one_modify_succeeds_async(self):
        server = Server('dummy_async')  # no schema
        connection_1 = Connection(server, user='cn=admin,o=lab', password='password', client_strategy=MOCK_ASYNC)
        connection_2 = Connection(server, user='cn=admin,o=lab', password='password', client_strategy=MOCK_ASYNC)
        connection_1.strategy.add_entry('cn=admin,o=lab', {'userPassword': 'password', 'sn': 'admin_sn'})
        connection_1.strategy.add_entry('cn=versioned,ou=test,o=lab', {'objectClass': 'person', 'cn': 'versioned', 'sn': 'original_sn', 'revision': '1'})
        connection_1.bind()
        connection_2.bind()
        dn = 'cn=versioned,ou=test,o=lab'
        controls = [assertion_control('(revision=1)')]
        _, result_1 = connection_1.get_response(connection_1.modify(dn, {'revision': (MODIFY_REPLACE, ['2']), 'sn': (MODIFY_REPLACE, ['modified-by-1'])}, controls=controls))
        _, result_2 = connection_2.get_response(connection_2.modify(dn, {'revision': (MODIFY_REPLACE, ['3']), 'sn': (MODIFY_REPLACE, ['modified-by-2'])}, controls=controls))
        self.assertEqual(result_1['result'], RESULT_SUCCESS)
        self.assertEqual(result_2['result'], RESULT_ASSERTION_FAILED)
        self.assertEqual(result_2['description'], 'assertionFailed')
        entry = server.dit[dn]
        self.assertEqual(entry['revision'], [b'2'])
        self.assertEqual(entry['sn'], [b'modified-by-1'])
        connection_1.unbind()
        connection_2.unbind()
