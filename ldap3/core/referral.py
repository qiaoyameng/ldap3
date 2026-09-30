"""
Referral target policy helpers.
"""

from .. import ANONYMOUS, SEQUENCE_TYPES, SIMPLE, STRING_TYPES
from .exceptions import LDAPReferralError


REFERRAL_REJECT = 'REJECT'
REFERRAL_ANONYMOUS = 'ANONYMOUS'
REFERRAL_USE_CREDENTIALS = 'USE_CREDENTIALS'

DEFAULT_REFERRAL_HOP_LIMIT = 10


def canonical_host(host):
    if host is None:
        return ''
    host = str(host).strip().lower()
    if host.endswith('.'):
        host = host[:-1]
    return host


def default_port(use_ssl):
    return 636 if use_ssl else 389


def referral_target(host, port, use_ssl, chain):
    use_ssl = bool(use_ssl)
    if port is None:
        port = default_port(use_ssl)
    return {
        'host': canonical_host(host),
        'port': int(port),
        'tls': use_ssl,
        'chain': list(chain or ())
    }


def referral_decision(target,
                      callback=None,
                      allowed_referral_hosts=None,
                      original_host=None,
                      original_credentials=False,
                      inherit_original_credentials=False):
    if callback is not None:
        if not callable(callback):
            raise LDAPReferralError('referral policy must be callable')
        decision = callback(target['host'], target['port'], target['tls'], target['chain'])
    else:
        decision = _default_decision(target, allowed_referral_hosts, original_host, original_credentials)

    return normalize_referral_decision(decision, target, inherit_original_credentials)


def _default_decision(target, allowed_referral_hosts, original_host, original_credentials):
    allowed = False
    for host, allow_authentication in allowed_referral_hosts or ():
        if host == '*' or canonical_host(host) == target['host']:
            allowed = True
            break

    if not allowed:
        return REFERRAL_REJECT

    if target['host'] == canonical_host(original_host) and original_credentials:
        return REFERRAL_USE_CREDENTIALS

    return REFERRAL_ANONYMOUS


def normalize_referral_decision(decision, target, inherit_original_credentials=False):
    credentials = None
    reason = None
    if isinstance(decision, STRING_TYPES):
        action = decision
    elif isinstance(decision, SEQUENCE_TYPES) and not isinstance(decision, (bytes, bytearray)):
        values = list(decision)
        if not values:
            action = REFERRAL_REJECT
        else:
            action = values[0]
            if len(values) > 1 and values[1] is not None:
                credentials = values[1]
            if len(values) > 2 and values[2] is not None:
                reason = str(values[2])
    elif isinstance(decision, dict):
        action = decision.get('action', decision.get('decision'))
        credentials = decision.get('credentials')
        reason_value = decision.get('reason')
        reason = str(reason_value) if reason_value is not None else None
    elif hasattr(decision, 'action') and not isinstance(decision, STRING_TYPES):
        action = getattr(decision, 'action')
        credentials = getattr(decision, 'credentials', None)
        reason_value = getattr(decision, 'reason', None)
        reason = str(reason_value) if reason_value is not None else None
    else:
        raise LDAPReferralError('invalid referral policy decision for %s:%d' % (target['host'], target['port']))

    if isinstance(action, STRING_TYPES):
        action = action.upper().replace('-', '_')

    if action not in (REFERRAL_REJECT, REFERRAL_ANONYMOUS, REFERRAL_USE_CREDENTIALS):
        raise LDAPReferralError('invalid referral policy decision for %s:%d' % (target['host'], target['port']))

    resolved_credentials = None
    if action == REFERRAL_USE_CREDENTIALS:
        if credentials is None and inherit_original_credentials:
            resolved_credentials = None
        elif credentials is None:
            raise LDAPReferralError('referral credentials are required for %s:%d' % (target['host'], target['port']))
        else:
            resolved_credentials = _normalize_credentials(credentials, target)

    return {
        'action': action,
        'credentials': resolved_credentials,
        'reason': reason
    }


def _normalize_credentials(credentials, target):
    if credentials is None:
        return None

    if isinstance(credentials, STRING_TYPES):
        return {
            'user': credentials,
            'password': None,
            'authentication': SIMPLE
        }

    if isinstance(credentials, dict):
        user = credentials.get('user', credentials.get('username'))
        password = credentials.get('password')
        authentication = credentials.get('authentication', SIMPLE)
        sasl_mechanism = credentials.get('sasl_mechanism')
        sasl_credentials = credentials.get('sasl_credentials')
    elif isinstance(credentials, SEQUENCE_TYPES):
        values = list(credentials)
        user = values[0] if len(values) > 0 else None
        password = values[1] if len(values) > 1 else None
        authentication = values[2] if len(values) > 2 and values[2] is not None else SIMPLE
        sasl_mechanism = values[3] if len(values) > 3 else None
        sasl_credentials = values[4] if len(values) > 4 else None
    else:
        raise LDAPReferralError('invalid referral credentials for %s:%d' % (target['host'], target['port']))

    if not user:
        raise LDAPReferralError('referral credentials require a user name for %s:%d' % (target['host'], target['port']))

    if authentication == ANONYMOUS:
        authentication = SIMPLE

    return {
        'user': user,
        'password': password,
        'authentication': authentication,
        'sasl_mechanism': sasl_mechanism,
        'sasl_credentials': sasl_credentials
    }
