import unittest
from types import SimpleNamespace

from ldap3 import ANONYMOUS, SIMPLE, SUBTREE, REFERRAL_ANONYMOUS, REFERRAL_REJECT, REFERRAL_USE_CREDENTIALS
from ldap3.core.exceptions import LDAPReferralError, LDAPSocketOpenError
from ldap3.core import connection as connection_module
from ldap3.strategy import base as strategy_base
from ldap3.strategy.base import BaseStrategy


class FakeReferralConnection(object):
    def __init__(self, **kwargs):
        self.server = kwargs['server']
        self.user = kwargs.get('user')
        self.password = kwargs.get('password')
        self.authentication = kwargs.get('authentication')
        self.sasl_mechanism = kwargs.get('sasl_mechanism')
        self.referral_policy = kwargs.get('referral_policy')
        self.referral_hop_limit = kwargs.get('referral_hop_limit')
        self.auto_referrals = kwargs.get('auto_referrals', True)
        self.request = None
        self.tls_started = False
        self.read_only = kwargs.get('read_only', False)
        self.check_names = kwargs.get('check_names', True)
        self.raise_exceptions = kwargs.get('raise_exceptions', False)
        self.fast_decoder = kwargs.get('fast_decoder', True)
        self.receive_timeout = kwargs.get('receive_timeout')
        self.use_referral_cache = kwargs.get('use_referral_cache', False)
        self.source_address = kwargs.get('source_address', '')
        self.source_port_list = kwargs.get('source_port_list', [0])
        self.start_tls_calls = 0
        self.open_calls = []
        self.bound = False
        self.last_error = None
        self.response = []
        self.result = {'result': 0, 'description': 'success', 'type': 'searchResultDone'}
        self.strategy = SimpleNamespace(_referrals=None,
                                        _referral_connection=False,
                                        _referral_chain=[],
                                        _referral_hop_count=0)

    def open(self, read_server_info=True):
        self.open_calls.append(read_server_info)

    def start_tls(self, read_server_info=True):
        self.start_tls_calls += 1
        self.tls_started = True
        return True

    def bind(self):
        self.bound = True

    def unbind(self):
        self.bound = False

    def search(self, *args, **kwargs):
        return True


class ReferralPolicyTest(unittest.TestCase):
    def setUp(self):
        self.connections = []
        self.original_connection_class = connection_module.Connection

        def connection_factory(*args, **kwargs):
            connection = FakeReferralConnection(**kwargs)
            self.connections.append(connection)
            return connection

        connection_module.Connection = connection_factory

    def tearDown(self):
        connection_module.Connection = self.original_connection_class

    def strategy(self, host='root.example', port=389, use_ssl=False, tls_started=False,
                 policy=None, hop_limit=10, allowed_referral_hosts=None):
        server = SimpleNamespace(host=host,
                                 port=port,
                                 ssl=use_ssl,
                                 tls_started=tls_started,
                                 tls=SimpleNamespace(private_key_file=None,
                                                     certificate_file=None,
                                                     validate=0,
                                                     version=None,
                                                     ca_certs_file=None),
                                 get_info=0,
                                 custom_formatter=None,
                                 connect_timeout=None,
                                 mode=None,
                                 allowed_referral_hosts=allowed_referral_hosts or [('*', True)])
        connection = SimpleNamespace(server=server,
                                     user='cn=root',
                                     password='root-password',
                                     authentication=SIMPLE,
                                     version=3,
                                     bound=True,
                                     tls_started=tls_started,
                                     auto_referrals=True,
                                     read_only=False,
                                     check_names=True,
                                     raise_exceptions=False,
                                     fast_decoder=True,
                                     receive_timeout=None,
                                     sasl_mechanism=None,
                                     sasl_credentials=None,
                                     use_referral_cache=False,
                                     referral_policy=policy,
                                     referral_hop_limit=hop_limit,
                                     source_address='',
                                     source_port_list=[0],
                                     usage=None,
                                     last_error=None,
                                     request={'type': 'searchRequest'})
        strategy = BaseStrategy(connection)
        strategy._initialize_referral_chain()
        return strategy

    def test_cross_referral_defaults_to_anonymous(self):
        strategy = self.strategy()

        referral, connection, _ = strategy.create_referral_connection(['ldap://other.example/dc=other'])

        self.assertEqual(referral['host'], 'other.example')
        self.assertIsNone(connection.user)
        self.assertIsNone(connection.password)
        self.assertEqual(connection.authentication, ANONYMOUS)

    def test_cross_referral_does_not_inherit_unbound_credentials(self):
        strategy = self.strategy()
        strategy.connection.bound = False
        _, connection, _ = strategy.create_referral_connection(['ldap://other.example/dc=other'])

        self.assertIsNone(connection.user)
        self.assertEqual(connection.authentication, ANONYMOUS)

    def test_policy_can_supply_different_credentials(self):
        decisions = []

        def policy(host, port, tls, chain):
            decisions.append((host, port, tls, chain))
            return REFERRAL_USE_CREDENTIALS, {
                'user': 'cn=referral',
                'password': 'referral-password'
            }

        strategy = self.strategy(policy=policy)
        _, connection, _ = strategy.create_referral_connection(['ldap://other.example/dc=other'])

        self.assertEqual(decisions[0][0], 'other.example')
        self.assertEqual(decisions[0][1], 389)
        self.assertFalse(decisions[0][2])
        self.assertEqual([(endpoint['host'], endpoint['port'], endpoint['tls']) for endpoint in decisions[0][3]],
                         [('root.example', 389, False)])
        self.assertEqual(connection.user, 'cn=referral')
        self.assertEqual(connection.password, 'referral-password')
        self.assertEqual(connection.authentication, SIMPLE)

    def test_policy_use_credentials_requires_explicit_credentials(self):
        strategy = self.strategy(policy=lambda host, port, tls, chain: REFERRAL_USE_CREDENTIALS)

        with self.assertRaises(LDAPReferralError) as caught:
            strategy.create_referral_connection(['ldap://other.example/dc=other'])

        self.assertIn('referral credentials are required', str(caught.exception))
        self.assertIn('search operation', str(caught.exception))

    def test_chain_is_passed_across_referral_operation(self):
        chains = []

        def policy(host, port, tls, chain):
            chains.append([(endpoint['host'], endpoint['port'], endpoint['tls']) for endpoint in chain])
            return REFERRAL_ANONYMOUS

        strategy = self.strategy(policy=policy)
        _, first_connection, _ = strategy.create_referral_connection(['ldap://first.example/dc=first'])
        self.assertEqual(chains[-1], [('root.example', 389, False)])

        nested = BaseStrategy(first_connection)
        nested._referral_connection = True
        nested._referral_chain = first_connection.strategy._referral_chain
        nested._referral_hop_count = first_connection.strategy._referral_hop_count
        nested.valid_referral_list(['ldap://second.example/dc=second'])

        self.assertEqual(chains, [
            [('root.example', 389, False)],
            [('root.example', 389, False), ('first.example', 389, False)]
        ])

    def test_default_port_is_equivalent_for_loop_detection(self):
        strategy = self.strategy()
        strategy._referral_chain = [{
            'host': 'root.example',
            'port': 389,
            'tls': False
        }]

        self.assertEqual(strategy.valid_referral_list(['ldap://root.example:389/dc=root']), [])

    def test_policy_rejection_keeps_original_referral_result(self):
        strategy = self.strategy(policy=lambda host, port, tls, chain: REFERRAL_REJECT)

        response, result = strategy.do_operation_on_referral(
            {'type': 'searchRequest', 'base': 'dc=root', 'filter': '(objectClass=*)',
             'scope': SUBTREE, 'dereferenceAlias': 'NEVER', 'attributes': ['1.1'],
             'sizeLimit': 0, 'timeLimit': 0, 'typesOnly': False, 'controls': None},
            ['ldap://other.example/dc=other'])

        self.assertIsNone(response)
        self.assertIsNone(result)
        self.assertEqual(self.connections, [])

    def test_tls_referral_cannot_silently_downgrade(self):
        strategy = self.strategy(use_ssl=True, port=636)
        _, connection, _ = strategy.create_referral_connection(['ldap://other.example/dc=other'])

        self.assertFalse(connection.server.ssl)
        self.assertEqual(connection.start_tls_calls, 1)

    def test_loop_and_total_hop_limit_apply_to_one_operation(self):
        strategy = self.strategy(policy=lambda host, port, tls, chain: REFERRAL_ANONYMOUS, hop_limit=1)
        strategy._referral_chain = [
            {'host': 'root.example', 'port': 389, 'tls': False},
            {'host': 'first.example', 'port': 389, 'tls': False}
        ]
        strategy._referral_hop_count = 1

        with self.assertRaises(LDAPReferralError) as caught:
            strategy.create_referral_connection(['ldap://second.example/dc=second'])

        self.assertIn('maximum referral hop limit (1) exceeded', str(caught.exception))
        self.assertIn('search', str(caught.exception))

    def test_connection_error_keeps_original_operation_context(self):
        strategy = self.strategy()

        def failing_connection(*args, **kwargs):
            connection = FakeReferralConnection(**kwargs)
            connection.open = lambda read_server_info=True: (_ for _ in ()).throw(LDAPSocketOpenError('unable to connect'))
            return connection

        connection_module.Connection = failing_connection

        with self.assertRaises(LDAPReferralError) as caught:
            strategy.do_operation_on_referral(
                {'type': 'searchRequest', 'base': 'dc=root', 'filter': '(objectClass=*)',
                 'scope': SUBTREE, 'dereferenceAlias': 'NEVER', 'attributes': ['1.1'],
                 'sizeLimit': 0, 'timeLimit': 0, 'typesOnly': False, 'controls': None},
                ['ldap://other.example/dc=other'])

        self.assertIn('unable to connect', str(caught.exception))
        self.assertIn('search operation', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
