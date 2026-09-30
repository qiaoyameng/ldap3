import unittest
from unittest.mock import patch

from ldap3 import ANONYMOUS, SIMPLE, Server
from ldap3.strategy import base as base_strategy
from ldap3.strategy.base import BaseStrategy


class DummyUsage(object):
    def __init__(self):
        self.referrals_connections = 0
        self.referrals_followed = 0


class FakeReferralConnection(object):
    created = []

    def __init__(self, server=None, user=None, password=None, authentication=None,
                 referral_target_policy=None, max_referral_hops=None, **kwargs):
        self.server = server
        self.user = user
        self.password = password
        self.authentication = authentication
        self.auto_referrals = kwargs.get('auto_referrals')
        self.raise_exceptions = kwargs.get('raise_exceptions')
        self.tls_started = False
        self.bound = False
        self.response = []
        self.result = {'result': 0, 'description': 'success', 'type': 'searchResultDone'}
        self.strategy = self
        self.start_tls_called = False
        FakeReferralConnection.created.append(self)

    def open(self):
        return True

    def start_tls(self):
        self.start_tls_called = True
        self.tls_started = True
        return True

    def bind(self):
        self.bound = True
        return True

    def search(self, base, search_filter, scope, dereference_alias,
               attributes, size_limit, time_limit, types_only, controls=None):
        self.search_arguments = (base, search_filter, scope, dereference_alias,
                                 attributes, size_limit, time_limit, types_only, controls)
        self.response = [{'dn': base, 'type': 'searchResEntry'}]
        return True

    def unbind(self):
        return True


class DummyConnection(object):
    def __init__(self, host='root.example', port=389, ssl=False, tls_started=False,
                 policy=None, max_hops=None, bound=True, user='root-user', password='root-password'):
        self.server = Server(host, port=port, use_ssl=ssl, get_info='NO_INFO',
                             referral_target_policy=policy, max_referral_hops=max_hops)
        self.user = user
        self.password = password
        self.authentication = SIMPLE
        self.version = 3
        self.auto_referrals = True
        self.read_only = False
        self.check_names = False
        self.raise_exceptions = False
        self.fast_decoder = True
        self.receive_timeout = None
        self.sasl_mechanism = None
        self.sasl_credentials = None
        self.bound = bound
        self.tls_started = tls_started
        self.use_referral_cache = False
        self.referral_target_policy = policy
        self.max_referral_hops = max_hops
        self.last_error = None
        self.usage = True
        self._usage = DummyUsage()
        self.request = None
        self.response = None
        self.result = None


class TestReferralPolicy(unittest.TestCase):
    def make_strategy(self, **kwargs):
        return BaseStrategy(DummyConnection(**kwargs))

    def request(self):
        return {
            'type': 'searchRequest',
            'base': 'ou=people,dc=example,dc=com',
            'filter': '(objectClass=person)',
            'scope': 2,
            'dereferenceAlias': 0,
            'attributes': ['uid'],
            'sizeLimit': 0,
            'timeLimit': 0,
            'typesOnly': False,
            'controls': []
        }

    def original_result(self):
        return {
            'result': 10,
            'description': 'referral',
            'type': 'searchResultDone',
            'dn': '',
            'message': '',
            'referrals': []
        }

    @patch("ldap3.core.connection.Connection", FakeReferralConnection)
    def test_cross_referral_uses_policy_credentials(self):
        calls = []

        def policy(host, port, tls, chain):
            calls.append((host, port, tls, chain))
            return 'other-user', 'other-password'

        strategy = self.make_strategy(host='root.example', policy=policy)
        FakeReferralConnection.created = []
        response, result = strategy.do_operation_on_referral(
            self.request(),
            ['ldap://other.example/ou=other?sub?sub'],
            self.original_result())

        self.assertEqual(result['result'], 0)
        self.assertEqual(response[0]['dn'], 'ou=other')
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0:3], ('other.example', 389, False))
        self.assertEqual(calls[0][3], (('root.example', 389, False),))
        target = FakeReferralConnection.created[0]
        self.assertEqual(target.user, 'other-user')
        self.assertEqual(target.password, 'other-password')
        self.assertEqual(target.authentication, SIMPLE)
        self.assertEqual(target.server.referral_target_policy, policy)
        self.assertEqual(target.server.max_referral_hops, 10)

    def test_default_ports_are_equivalent_for_cycle_detection(self):
        strategy = self.make_strategy(host='root.example')
        strategy.valid_referral_list(['ldap://root.example:389'])
        self.assertEqual(strategy._referral_limits_exceeded, 'referral cycle detected')
        self.assertEqual(strategy.valid_referral_list([]), [])
        self.assertEqual(strategy._referral_chain[-1], ('root.example', 389, False))

    def test_policy_rejection_preserves_original_operation_context(self):
        def policy(host, port, tls, chain):
            self.assertEqual((host, port, tls), ('blocked.example', 389, False))
            self.assertEqual(chain, (('root.example', 389, False),))
            return False

        strategy = self.make_strategy(policy=policy)
        original_result = self.original_result()
        response, result = strategy.do_operation_on_referral(
            self.request(),
            ['ldap://blocked.example'],
            original_result)

        self.assertIsNone(response)
        self.assertEqual(result['result'], 10)
        self.assertEqual(result['type'], 'searchResultDone')
        self.assertIn('searchRequest', result['message'])
        self.assertIn('ou=people,dc=example,dc=com', result['message'])
        self.assertIn('blocked.example:389', result['message'])
        self.assertIn('rejected by referral target policy', result['message'])
        self.assertIn("('root.example', 389, False)", result['message'])
        self.assertEqual(strategy.connection.last_error, result['message'])

    @patch("ldap3.core.connection.Connection", FakeReferralConnection)
    def test_tls_referral_does_not_silently_downgrade(self):
        calls = []

        def policy(host, port, tls, chain):
            calls.append((host, port, tls, chain))
            return None

        strategy = self.make_strategy(host='secure.example', ssl=True, policy=policy)
        FakeReferralConnection.created = []
        strategy.do_operation_on_referral(
            self.request(),
            ['ldap://clear.example'],
            self.original_result())

        target = FakeReferralConnection.created[0]
        self.assertEqual(calls[0][0:3], ('clear.example', 389, True))
        self.assertFalse(target.server.ssl)
        self.assertTrue(target.start_tls_called)
        self.assertTrue(target.tls_started)
        self.assertTrue(target.strategy._referral_chain[-1][2])

    @patch("ldap3.core.connection.Connection", FakeReferralConnection)
    def test_default_cross_domain_referral_is_anonymous(self):
        strategy = self.make_strategy()
        FakeReferralConnection.created = []
        strategy.do_operation_on_referral(
            self.request(),
            ['ldap://other.example'],
            self.original_result())

        target = FakeReferralConnection.created[0]
        self.assertIsNone(target.user)
        self.assertIsNone(target.password)
        self.assertEqual(target.authentication, ANONYMOUS)

    @patch("ldap3.core.connection.Connection", FakeReferralConnection)
    def test_explicit_legacy_allowed_host_can_inherit_credentials(self):
        strategy = self.make_strategy()
        strategy.connection.server.allowed_referral_hosts = [('*', True)]
        FakeReferralConnection.created = []
        strategy.do_operation_on_referral(
            self.request(),
            ['ldap://other.example'],
            self.original_result())

        target = FakeReferralConnection.created[0]
        self.assertEqual(target.user, 'root-user')
        self.assertEqual(target.password, 'root-password')
        self.assertEqual(target.authentication, SIMPLE)

    @patch("ldap3.core.connection.Connection", FakeReferralConnection)
    def test_hop_limit_is_counted_for_whole_operation(self):
        FakeReferralConnection.created = []
        strategy = self.make_strategy(max_hops=1)
        strategy._referral_chain = [('root.example', 389, False), ('first.example', 389, False)]

        selected, target, cachekey = strategy.create_referral_connection(['ldap://second.example'])
        self.assertIsNone(selected)
        self.assertIsNone(target)
        self.assertIsNone(cachekey)

        response, result = strategy.do_operation_on_referral(
            self.request(),
            ['ldap://second.example'],
            self.original_result())

        self.assertIsNone(response)
        self.assertEqual(result['result'], 10)
        self.assertIn('maximum referral hops (1) reached', result['message'])
        self.assertEqual(FakeReferralConnection.created, [])
