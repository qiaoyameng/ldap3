"""
Tests for the LDAP Server Side Sorting controls (RFC 2891) used together with
the simple paged results control (RFC 2696).
"""

# Created on 2026.09.30

import unittest

from ldap3 import Server, Connection, MOCK_SYNC, MOCK_ASYNC, SUBTREE, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPSortControlError, LDAPControlError
from ldap3.protocol.rfc2891 import sort_request_control, sort_response_control, \
    sort_request_to_list, sort_response_to_dict, SORT_REQUEST_CONTROL, SORT_RESPONSE_CONTROL, \
    SORT_RESULT_SUCCESS, SORT_RESULT_NO_SUCH_ATTRIBUTE, SORT_RESULT_INAPPROPRIATE_MATCHING
from ldap3.strategy.base import BaseStrategy

PAGED_CONTROL = '1.2.840.113556.1.4.319'


def add_sort_fixture(connection):
    # five entries share the primary key 'dept', secondary key 'uid' disambiguates them
    # cn=e4 misses the secondary attribute, cn=e6 ties with cn=e3 on both keys
    entries = (
        ('cn=e1,ou=people,o=lab', {'dept': 'eng', 'uid': '001', 'sn': 'Smith'}),
        ('cn=e2,ou=people,o=lab', {'dept': 'eng', 'uid': '003', 'sn': 'Smith'}),
        ('cn=e3,ou=people,o=lab', {'dept': 'eng', 'uid': '002', 'sn': 'jones'}),
        ('cn=e4,ou=people,o=lab', {'dept': 'eng'}),
        ('cn=e5,ou=people,o=lab', {'dept': 'sales', 'uid': '010'}),
        ('cn=e6,ou=people,o=lab', {'dept': 'eng', 'uid': '002', 'sn': 'adams'}),
    )
    for dn, attributes in entries:
        connection.strategy.add_entry(dn, attributes)


class TestSortControlEncoding(unittest.TestCase):
    def test_request_control_roundtrip(self):
        control = sort_request_control(['sn',
                                        ('givenName', None, True),
                                        {'attribute_type': 'cn', 'ordering_rule': '2.5.13.3'}])
        oid, info = BaseStrategy.decode_control(control)
        self.assertEqual(oid, SORT_REQUEST_CONTROL)
        self.assertTrue(info['criticality'])
        sort_keys = sort_request_to_list(info['value'])
        self.assertEqual(sort_keys, [{'attr': 'sn', 'ordering_rule': None, 'reverse_order': False},
                                     {'attr': 'givenName', 'ordering_rule': None, 'reverse_order': True},
                                     {'attr': 'cn', 'ordering_rule': '2.5.13.3', 'reverse_order': False}])

    def test_response_control_roundtrip(self):
        for result_code, attribute in ((SORT_RESULT_SUCCESS, None),
                                       (SORT_RESULT_NO_SUCH_ATTRIBUTE, 'bogus')):
            oid, info = BaseStrategy.decode_control(sort_response_control(result_code, attribute))
            self.assertEqual(oid, SORT_RESPONSE_CONTROL)
            self.assertEqual(sort_response_to_dict(info['value']), {'result': result_code, 'attr': attribute})

    def test_empty_sort_order_rejected(self):
        self.assertRaises(LDAPControlError, sort_request_control, [])

    def test_invalid_sort_key_rejected(self):
        self.assertRaises(LDAPControlError, sort_request_control, [42])


class TestMockSortedPagedSearch(unittest.TestCase):
    def setUp(self):
        self.server = Server('MockSortServer')
        self.connection = Connection(self.server, client_strategy=MOCK_SYNC)
        self.connection.bind()
        add_sort_fixture(self.connection)

    def tearDown(self):
        self.connection.unbind()

    def paged_dns(self, sort_order, paged_size=2):
        return [entry['dn'] for entry in
                self.connection.extend.standard.paged_search('o=lab', '(cn=*)', SUBTREE,
                                                             attributes=['dept', 'uid', 'sn'],
                                                             paged_size=paged_size,
                                                             sort_order=sort_order)]

    def test_multi_key_sort_is_stable_across_pages(self):
        dns = self.paged_dns([('dept',), ('uid',), ('sn', '2.5.13.3')])
        # same primary value 'eng' is disambiguated by uid, the uid tie between e3 and e6 is
        # broken by sn, missing uid goes last, 'sales' follows the whole 'eng' group
        self.assertEqual(dns, ['cn=e1,ou=people,o=lab',
                               'cn=e6,ou=people,o=lab',
                               'cn=e3,ou=people,o=lab',
                               'cn=e2,ou=people,o=lab',
                               'cn=e4,ou=people,o=lab',
                               'cn=e5,ou=people,o=lab'])
        # no entry lost nor duplicated while paging
        self.assertEqual(len(dns), 6)
        self.assertEqual(len(set(dns)), 6)

    def test_reverse_secondary_key(self):
        dns = self.paged_dns(['dept', ('uid', None, True), ('sn', None, True)])
        self.assertEqual(dns[0], 'cn=e4,ou=people,o=lab')  # missing attribute comes first descending
        self.assertEqual(dns[1], 'cn=e2,ou=people,o=lab')   # greatest uid 003
        self.assertEqual(set(dns[2:4]), {'cn=e3,ou=people,o=lab', 'cn=e6,ou=people,o=lab'})  # uid 002
        self.assertEqual(dns[4], 'cn=e1,ou=people,o=lab')  # lowest uid 001
        self.assertEqual(dns[5], 'cn=e5,ou=people,o=lab')  # sales is last in the descending group
        self.assertEqual(len(set(dns)), 6)

    def test_ordering_rule_oid_case_ignore(self):
        dns = self.paged_dns([('sn', '2.5.13.3')], paged_size=3)
        # adams < jones < Smith (folded to 'smith'); e1/e2 share the same sn and stay tied
        self.assertEqual(dns[0], 'cn=e6,ou=people,o=lab')
        self.assertEqual(dns[1], 'cn=e3,ou=people,o=lab')
        self.assertEqual(set(dns[2:4]), {'cn=e1,ou=people,o=lab', 'cn=e2,ou=people,o=lab'})
        self.assertEqual(set(dns[4:]), {'cn=e4,ou=people,o=lab', 'cn=e5,ou=people,o=lab'})  # missing sn sorts last

    def test_ordering_rule_oid_case_exact(self):
        dns = self.paged_dns([('sn', '2.5.13.6')])
        # uppercase 'Smith' precedes lowercase values; e1 and e2 share that exact value
        self.assertEqual(set(dns[:2]), {'cn=e1,ou=people,o=lab', 'cn=e2,ou=people,o=lab'})

    def test_integer_ordering_rule(self):
        dns = self.paged_dns([('uid', '2.5.13.15')], paged_size=6)
        self.assertEqual(dns[0], 'cn=e1,ou=people,o=lab')
        self.assertEqual(set(dns[1:3]), {'cn=e3,ou=people,o=lab', 'cn=e6,ou=people,o=lab'})
        self.assertEqual(dns[3], 'cn=e2,ou=people,o=lab')
        self.assertEqual(dns[4], 'cn=e5,ou=people,o=lab')
        self.assertEqual(dns[5], 'cn=e4,ou=people,o=lab')  # missing uid sorts last

    def test_sort_failure_returns_no_entries(self):
        # a failed sort must never yield a batch of seemingly ordered entries
        received = []
        with self.assertRaises(LDAPSortControlError):
            for entry in self.connection.extend.standard.paged_search('o=lab', '(cn=*)', SUBTREE,
                                                                      attributes=ALL_ATTRIBUTES,
                                                                      paged_size=2,
                                                                      sort_order=['notAnAttribute']):
                received.append(entry)
        self.assertListEqual(received, [])

    def test_unknown_ordering_rule_returns_no_entries(self):
        received = []
        with self.assertRaises(LDAPSortControlError):
            for entry in self.connection.extend.standard.paged_search('o=lab', '(cn=*)', SUBTREE,
                                                                      attributes=['uid'],
                                                                      paged_size=2,
                                                                      sort_order=[('uid', '9.9.9.9')]):
                received.append(entry)
        self.assertListEqual(received, [])

    def test_sort_result_control_reported_on_failure(self):
        control = sort_request_control(['notAnAttribute'])
        self.connection.search('o=lab', '(cn=*)', SUBTREE, attributes=['uid'],
                               controls=[control], paged_size=2)
        self.assertEqual(self.connection.response, [])
        sort_value = self.connection.result['controls'][SORT_RESPONSE_CONTROL]['value']
        self.assertEqual(sort_value['result'], SORT_RESULT_NO_SUCH_ATTRIBUTE)
        self.assertEqual(sort_value['attr'], 'notAnAttribute')
        self.assertEqual(self.connection.result['controls'][PAGED_CONTROL]['value']['cookie'], b'')

    def test_inappropriate_matching_reported(self):
        control = sort_request_control([('uid', '9.9.9.9')])
        self.connection.search('o=lab', '(cn=*)', SUBTREE, attributes=['uid'], controls=[control])
        sort_value = self.connection.result['controls'][SORT_RESPONSE_CONTROL]['value']
        self.assertEqual(sort_value['result'], SORT_RESULT_INAPPROPRIATE_MATCHING)
        self.assertEqual(sort_value['attr'], 'uid')

    def test_cookie_rejected_when_sort_order_changes(self):
        # first page sorted by dept+uid
        control = sort_request_control(['dept', 'uid'])
        self.connection.search('o=lab', '(cn=*)', SUBTREE, attributes=['dept', 'uid'],
                               controls=[control], paged_size=2)
        cookie = self.connection.result['controls'][PAGED_CONTROL]['value']['cookie']
        self.assertTrue(cookie)

        # reusing the same cookie with a different sort order is forbidden
        self.connection.search('o=lab', '(cn=*)', SUBTREE, attributes=['dept', 'uid'],
                               controls=[sort_request_control(['uid'])], paged_size=2, paged_cookie=cookie)
        self.assertEqual(self.connection.result['result'], 1)
        self.assertEqual(self.connection.response, [])

        # reusing the cookie without any sort control is forbidden as well
        self.connection.search('o=lab', '(cn=*)', SUBTREE, attributes=['dept', 'uid'],
                               paged_size=2, paged_cookie=cookie)
        self.assertEqual(self.connection.result['result'], 1)
        self.assertEqual(self.connection.response, [])

    def test_cookie_valid_with_same_sort_order(self):
        sort_order = ['dept', 'uid', ('sn', '2.5.13.3')]
        control = sort_request_control(sort_order)
        self.connection.search('o=lab', '(cn=*)', SUBTREE, attributes=['dept', 'uid', 'sn'],
                               controls=[control], paged_size=2)
        cookie = self.connection.result['controls'][PAGED_CONTROL]['value']['cookie']
        first_page = [entry['dn'] for entry in self.connection.response]

        self.connection.search('o=lab', '(cn=*)', SUBTREE, attributes=['dept', 'uid', 'sn'],
                               controls=[sort_request_control(sort_order)],
                               paged_size=2, paged_cookie=cookie)
        # every page carries the sort response control
        self.assertEqual(self.connection.result['controls'][SORT_RESPONSE_CONTROL]['value']['result'],
                         SORT_RESULT_SUCCESS)
        second_page = [entry['dn'] for entry in self.connection.response]
        self.assertEqual(first_page, ['cn=e1,ou=people,o=lab', 'cn=e6,ou=people,o=lab'])
        self.assertEqual(second_page, ['cn=e3,ou=people,o=lab', 'cn=e2,ou=people,o=lab'])
        self.assertFalse(set(first_page) & set(second_page))


    def test_sorted_search_with_empty_result_set(self):
        # sorting an empty result set always succeeds and returns no entry
        self.connection.strategy.add_entry('ou=empty,o=lab', {'ou': 'empty'})
        dns = [entry['dn'] for entry in
               self.connection.extend.standard.paged_search('ou=empty,o=lab', '(cn=nomatch*)', SUBTREE,
                                                            attributes=['cn'], paged_size=2,
                                                            sort_order=['cn'])]
        self.assertListEqual(dns, [])

    def test_non_paged_sorted_search(self):
        self.connection.search('o=lab', '(cn=*)', SUBTREE, attributes=['dept', 'uid', 'sn'],
                               controls=[sort_request_control(['dept', 'uid', ('sn', '2.5.13.3')])])
        dns = [entry['dn'] for entry in self.connection.response]
        self.assertEqual(dns, ['cn=e1,ou=people,o=lab',
                               'cn=e6,ou=people,o=lab',
                               'cn=e3,ou=people,o=lab',
                               'cn=e2,ou=people,o=lab',
                               'cn=e4,ou=people,o=lab',
                               'cn=e5,ou=people,o=lab'])
        self.assertEqual(self.connection.result['controls'][SORT_RESPONSE_CONTROL]['value']['result'],
                         SORT_RESULT_SUCCESS)


class TestMockAsyncSortedPagedSearch(unittest.TestCase):
    def test_multi_key_sort_on_mock_async(self):
        server = Server('MockAsyncSortServer')
        connection = Connection(server, client_strategy=MOCK_ASYNC)
        connection.bind()
        add_sort_fixture(connection)
        dns = [entry['dn'] for entry in
               connection.extend.standard.paged_search('o=lab', '(cn=*)', SUBTREE,
                                                       attributes=['dept', 'uid', 'sn'],
                                                       paged_size=3,
                                                       sort_order=['dept', 'uid', ('sn', '2.5.13.3')])]
        self.assertEqual(dns, ['cn=e1,ou=people,o=lab',
                               'cn=e6,ou=people,o=lab',
                               'cn=e3,ou=people,o=lab',
                               'cn=e2,ou=people,o=lab',
                               'cn=e4,ou=people,o=lab',
                               'cn=e5,ou=people,o=lab'])
        self.assertEqual(len(dns), 6)
        self.assertEqual(len(set(dns)), 6)
        connection.unbind()
